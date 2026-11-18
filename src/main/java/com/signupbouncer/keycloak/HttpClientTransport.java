package com.signupbouncer.keycloak;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.net.URI;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.Semaphore;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Supplier;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.Configurable;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.entity.InputStreamEntity;

/**
 * The HTTP call through Keycloak's own outgoing HTTP client (the connectionsHttpClient SPI's HttpClientProvider), as
 * Keycloak's reCAPTCHA step makes its call. So the call follows the admin's proxy-mappings (or the HTTPS_PROXY,
 * HTTP_PROXY and NO_PROXY variables Keycloak reads when there are none), the proxy's credentials, and Keycloak's
 * truststore, exactly like Keycloak's other outgoing calls.
 *
 * <p>Each request overrides three things of the shared client for this call only: it never follows a redirect (a
 * redirect is a failed check: the key and the address go nowhere else, even where an admin set allow-redirects), every
 * timeout is the deadline, and it stops reading an answer as soon as it passes maxBytes.
 *
 * <p>The whole call, choosing the proxy included, runs on a small pool of its own, and the registration waits for it
 * with the deadline. When it stops waiting, it aborts the request: a request aborted before it reached the network
 * never connects, and one in flight has its connection closed. When MAX_CALLS calls are already in flight, a call
 * waits for one of them to end, inside the same deadline. If none ends in time, it sends nothing, throws
 * Transport.Busy, and the signup goes through.
 */
public final class HttpClientTransport implements Transport {

  /** At most this many calls in flight at once; one more waits for a free slot, inside its deadline. */
  static final int MAX_CALLS = 64;

  private final Supplier<HttpClient> client;
  private final CallPool callers;
  private final int maxBytes;

  /**
   * client: called on the registration's own thread, once per call, so it may read the Keycloak session. callers: the
   * pool from newCallPool(), shared by every registration.
   */
  HttpClientTransport(Supplier<HttpClient> client, CallPool callers, int maxBytes) {
    this.client = client;
    this.callers = callers;
    this.maxBytes = maxBytes;
  }

  /** The pool the calls run on: MAX_CALLS slots. */
  static CallPool newCallPool() {
    return new CallPool(MAX_CALLS);
  }

  /**
   * The threads the calls run on, shared by every registration, with one slot per thread. A call holds its slot until
   * its thread is done with it, even after the registration stopped waiting. A call with no free slot waits for one up
   * to its own deadline, first come first served, and one that gets none in time is never queued or sent.
   */
  static final class CallPool {
    private final Semaphore slots;
    private final ThreadPoolExecutor threads;

    CallPool(int size) {
      slots = new Semaphore(size, true);
      // A slot is taken before each task is handed over and given back after its thread ran it (afterExecute runs for
      // a task cancelled before it started too), so at most `size` tasks are ever queued or running. The queue holds a
      // task only for the moment between one ending and its thread taking the next.
      threads =
          new ThreadPoolExecutor(
              size,
              size,
              30,
              TimeUnit.SECONDS,
              new LinkedBlockingQueue<>(),
              r -> {
                Thread t = new Thread(r, "signupbouncer-check");
                t.setDaemon(true);
                return t;
              }) {
            @Override
            protected void afterExecute(Runnable r, Throwable t) {
              slots.release();
            }
          };
      threads.allowCoreThreadTimeOut(true);
    }

    /** Runs call on a pooled thread once a slot is free; null when none frees up by untilNanos (System.nanoTime). */
    <T> Future<T> submit(Callable<T> call, long untilNanos) throws InterruptedException {
      if (!slots.tryAcquire(Math.max(0, untilNanos - System.nanoTime()), TimeUnit.NANOSECONDS)) return null;
      boolean handedOver = false;
      try {
        // A slot that freed up only as the time ran out sends nothing.
        if (System.nanoTime() - untilNanos >= 0) return null;
        Future<T> f = threads.submit(call);
        handedOver = true;
        return f;
      } finally {
        // Also when submit throws an Error (no thread could be started): the slot is never lost.
        if (!handedOver) slots.release();
      }
    }

    void shutdownNow() {
      threads.shutdownNow();
    }
  }

  @Override
  public Answer post(URI uri, Map<String, String> headers, byte[] body, Duration deadline)
      throws IOException, TimeoutException, InterruptedException {
    long until = System.nanoTime() + deadline.toNanos();
    HttpClient http;
    try {
      http = client.get();
    } catch (RuntimeException | LinkageError e) {
      throw new IOException("no HTTP client", e);
    }
    if (http == null) throw new IOException("no HTTP client");
    HttpPost post = new HttpPost(uri);
    headers.forEach(post::setHeader);
    post.setEntity(entity(body, "https".equalsIgnoreCase(uri.getScheme())));
    AtomicBoolean gaveUp = new AtomicBoolean();
    Future<Answer> call;
    try {
      // Waiting for a slot counts against the deadline too.
      call = callers.submit(() -> exchange(http, post, gaveUp, until), until);
    } catch (RejectedExecutionException e) {
      throw new IOException("the check pool is shut down");
    }
    if (call == null) throw new Transport.Busy();
    try {
      // Covers choosing a proxy, connecting, the headers and the whole body.
      return call.get(Math.max(0, until - System.nanoTime()), TimeUnit.NANOSECONDS);
    } catch (TimeoutException | InterruptedException e) {
      gaveUp.set(true);
      // Aborting before the client reaches the network (a slow proxy choice) makes it stop there; aborting later
      // closes the connection. The worker also checks gaveUp, for an abort that lands between the two.
      post.abort();
      call.cancel(true);
      throw e;
    } catch (ExecutionException e) {
      Throwable cause = e.getCause();
      // Connect, pool and read timeouts are all InterruptedIOExceptions in HttpClient 4.
      if (cause instanceof InterruptedIOException) throw new TimeoutException("timed out");
      throw new IOException("request failed", cause);
    }
  }

  /**
   * The client's own defaults with this call's limits on top. A request's config replaces the client's whole default
   * config in HttpClient 4, so it starts from a copy. The proxy is not in it: Keycloak chooses the proxy in its route
   * planner, which a request config doesn't touch.
   */
  static RequestConfig requestConfig(HttpClient http, Duration deadline) {
    RequestConfig defaults = http instanceof Configurable c ? c.getConfig() : null;
    int ms = (int) Math.max(1, Math.min(Integer.MAX_VALUE, deadline.toMillis()));
    return (defaults == null ? RequestConfig.custom() : RequestConfig.copy(defaults))
        .setRedirectsEnabled(false)
        .setConnectTimeout(ms)
        .setConnectionRequestTimeout(ms)
        .setSocketTimeout(ms)
        .setExpectContinueEnabled(false)
        .build();
  }

  /**
   * The request body. sendOnce makes it one the client cannot send a second time: each check SignupBouncer answers is
   * counted, and an admin who sets Keycloak's max-retries above 0 gets a client that resends a POST already sent when
   * the connection drops before the answer, which would count the signup twice. Over https a proxy's login happens on
   * CONNECT, before the body goes out, so nothing else needs a second send. Over plain http (a local test server) a
   * proxy that asks for a login needs the body again, so there it stays repeatable.
   */
  static HttpEntity entity(byte[] body, boolean sendOnce) {
    return sendOnce ? new InputStreamEntity(new ByteArrayInputStream(body), body.length) : new ByteArrayEntity(body);
  }

  /** On a pooled thread: sends the request and reads the answer, up to maxBytes. */
  private Answer exchange(HttpClient http, HttpPost post, AtomicBoolean gaveUp, long until) throws IOException {
    // The client's own timeouts get only the time left after waiting for this slot; none left, nothing is sent.
    long left = until - System.nanoTime();
    if (gaveUp.get() || left <= 0) throw gaveUp(post);
    post.setConfig(requestConfig(http, Duration.ofNanos(left)));
    HttpResponse response = http.execute(post);
    try {
      if (gaveUp.get()) throw gaveUp(post);
      int status = response.getStatusLine().getStatusCode();
      HttpEntity entity = response.getEntity();
      return new Answer(status, entity == null ? new byte[0] : read(entity, post, gaveUp));
    } finally {
      // An answer read to its end has already left its connection to the client's pool; this closes any other.
      if (response instanceof Closeable c) {
        try {
          c.close();
        } catch (IOException | RuntimeException e) {
          // the connection is gone either way
        }
      }
    }
  }

  /** The body up to maxBytes, or null past that. */
  private byte[] read(HttpEntity entity, HttpPost post, AtomicBoolean gaveUp) throws IOException {
    if (entity.getContentLength() > maxBytes) {
      post.abort();
      return null;
    }
    ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    byte[] chunk = new byte[8192];
    // Not closed here: closing an unfinished body would read the rest of it. The end of the body hands the connection
    // back; on the other paths, abort() and the response's close() drop it.
    InputStream in = entity.getContent();
    if (in == null) return new byte[0];
    int n;
    while ((n = in.read(chunk)) != -1) {
      if (gaveUp.get()) throw gaveUp(post);
      if (buffer.size() + n > maxBytes) {
        post.abort();
        return null;
      }
      buffer.write(chunk, 0, n);
    }
    return buffer.toByteArray();
  }

  private static IOException gaveUp(HttpPost post) {
    post.abort();
    return new InterruptedIOException("gave up");
  }
}
