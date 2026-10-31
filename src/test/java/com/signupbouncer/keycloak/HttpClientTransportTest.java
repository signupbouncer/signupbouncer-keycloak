package com.signupbouncer.keycloak;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;
import org.apache.http.HttpException;
import org.apache.http.HttpHost;
import org.apache.http.HttpRequest;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.HttpClient;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.client.LaxRedirectStrategy;
import org.apache.http.impl.conn.DefaultRoutePlanner;
import org.apache.http.protocol.HttpContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * The real HTTP path (HttpClientTransport plus SignupCheck) against a local server, with Apache HttpClient 4 clients set
 * up the way Keycloak's DefaultHttpClientFactory sets up its own: deadlines, aborts, redirects, size cap, the client's
 * proxy and proxy credentials.
 */
class HttpClientTransportTest {

  private HttpServer server;
  private String base;
  private ExecutorService callers;
  private final List<CloseableHttpClient> clients = new CopyOnWriteArrayList<>();
  private final AtomicInteger redirectTargetHits = new AtomicInteger();

  @BeforeEach
  void start() throws IOException {
    server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.setExecutor(Executors.newCachedThreadPool());
    base = "http://127.0.0.1:" + server.getAddress().getPort();
    server.start();
    callers = HttpClientTransport.newCallPool();
  }

  @AfterEach
  void stop() throws IOException {
    server.stop(0);
    callers.shutdownNow();
    for (CloseableHttpClient c : clients) c.close();
  }

  private void route(String prefix, Handler h) {
    server.createContext(prefix, ex -> {
      try {
        h.handle(ex);
      } catch (Exception e) {
        // the client hung up
      } finally {
        ex.close();
      }
    });
  }

  interface Handler {
    void handle(HttpExchange ex) throws Exception;
  }

  private static void send(HttpExchange ex, int status, String body) throws IOException {
    byte[] b = body.getBytes(StandardCharsets.UTF_8);
    ex.getResponseHeaders().set("Content-Type", "application/json");
    ex.sendResponseHeaders(status, b.length == 0 ? -1 : b.length);
    if (b.length > 0) ex.getResponseBody().write(b);
  }

  /** A client like Keycloak's: its own default timeouts (5 s socket), redirects off, cookies off. */
  private CloseableHttpClient keycloakLike(HttpClientBuilder b) {
    CloseableHttpClient c =
        b.setDefaultRequestConfig(RequestConfig.custom().setSocketTimeout(5000).setExpectContinueEnabled(false).build())
            .disableCookieManagement()
            .build();
    clients.add(c);
    return c;
  }

  private CloseableHttpClient keycloakLike() {
    return keycloakLike(HttpClients.custom().disableRedirectHandling());
  }

  private Decision check(HttpClient client, String baseUrl) {
    return check(() -> client, baseUrl);
  }

  private Decision check(Supplier<HttpClient> client, String baseUrl) {
    HttpClientTransport transport = new HttpClientTransport(client, callers, SignupCheck.MAX_ANSWER_BYTES);
    return new SignupCheck(transport, baseUrl, SignupCheck.TIMEOUT, "signupbouncer-keycloak/test")
        .check(
            new SignupCheck.Settings("sb_live_test", null, true),
            new SignupCheck.Signup("ann@example.com", "203.0.113.7", "ua", null));
  }

  private Decision check(String path) {
    return check(keycloakLike(), base + path);
  }

  /** A route planner that takes as long as the given task, as a slow proxy choice would. */
  private static DefaultRoutePlanner slowPlanner(Runnable wait) {
    return new DefaultRoutePlanner(null) {
      @Override
      protected HttpHost determineProxy(HttpHost target, HttpRequest request, HttpContext context) throws HttpException {
        wait.run();
        return null;
      }
    };
  }

  @Test
  void aCompleteBlockRefuses() {
    route("/ok/v1/check", ex -> {
      String auth = ex.getRequestHeaders().getFirst("Authorization");
      String ua = ex.getRequestHeaders().getFirst("User-Agent");
      String type = ex.getRequestHeaders().getFirst("Content-Type");
      String body = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
      boolean good =
          "Bearer sb_live_test".equals(auth)
              && "signupbouncer-keycloak/test".equals(ua)
              && "application/json".equals(type)
              && body.contains("ann@example.com");
      send(ex, 200, good ? SignupCheckTest.answer("block").toString() : SignupCheckTest.answer("allow").toString());
    });
    Decision d = check("/ok");
    assertTrue(d.refuse());
    assertEquals("block", d.outcome());
  }

  @Test
  void aServerThatNeverAnswersGivesUpAfterOneAndAHalfSeconds() {
    route("/slow/v1/check", ex -> Thread.sleep(5000));
    long t = System.nanoTime();
    Decision d = check("/slow");
    long ms = (System.nanoTime() - t) / 1_000_000;
    assertFalse(d.refuse());
    assertEquals("timeout", d.outcome());
    assertTrue(ms >= 1400 && ms < 2500, "gave up after " + ms + " ms");
  }

  @Test
  void theCallGoesThroughTheClientsProxyWithItsCredentials() {
    // The test server plays the proxy. Like Keycloak's ProxyMappingsAwareRoutePlanner, the planner names the proxy and
    // puts its credentials in the request's context; the proxy asks for them first (407).
    List<String> seen = new CopyOnWriteArrayList<>();
    String expected = "Basic " + Base64.getEncoder().encodeToString("kc:secret".getBytes(StandardCharsets.UTF_8));
    route("/v1/check", ex -> {
      String auth = ex.getRequestHeaders().getFirst("Proxy-Authorization");
      seen.add(ex.getRequestURI() + " " + auth);
      if (!expected.equals(auth)) {
        ex.getResponseHeaders().set("Proxy-Authenticate", "Basic realm=\"proxy\"");
        ex.getRequestBody().readAllBytes();
        ex.sendResponseHeaders(407, -1);
        return;
      }
      send(ex, 200, SignupCheckTest.answer("block").toString());
    });
    HttpHost proxy = new HttpHost("127.0.0.1", server.getAddress().getPort());
    DefaultRoutePlanner planner =
        new DefaultRoutePlanner(null) {
          @Override
          protected HttpHost determineProxy(HttpHost target, HttpRequest request, HttpContext context) {
            BasicCredentialsProvider creds = new BasicCredentialsProvider();
            creds.setCredentials(
                new AuthScope(proxy.getHostName(), proxy.getPort()), new UsernamePasswordCredentials("kc", "secret"));
            context.setAttribute(HttpClientContext.CREDS_PROVIDER, creds);
            return proxy;
          }
        };
    // signupbouncer.invalid can't resolve: only a call through the proxy gets an answer.
    Decision d = check(keycloakLike(HttpClients.custom().disableRedirectHandling().setRoutePlanner(planner)), "http://signupbouncer.invalid");
    assertEquals("block", d.outcome(), "seen: " + seen);
    assertTrue(d.refuse());
    assertEquals("http://signupbouncer.invalid/v1/check " + expected, seen.get(seen.size() - 1));
  }

  @Test
  void aSlowProxyChoiceIsInsideTheDeadline() {
    route("/ok/v1/check", ex -> send(ex, 200, SignupCheckTest.answer("block").toString()));
    CloseableHttpClient client =
        keycloakLike(
            HttpClients.custom()
                .disableRedirectHandling()
                .setRoutePlanner(
                    slowPlanner(() -> {
                      try {
                        Thread.sleep(3000);
                      } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                      }
                    })));
    long t = System.nanoTime();
    Decision d = check(client, base + "/ok");
    long ms = (System.nanoTime() - t) / 1_000_000;
    assertFalse(d.refuse());
    assertEquals("timeout", d.outcome());
    assertTrue(ms >= 1400 && ms < 2000, "gave up after " + ms + " ms");
  }

  @Test
  void aProxyChoiceThatReturnsAfterTheDeadlineSendsNothing() throws InterruptedException {
    AtomicInteger answering = new AtomicInteger();
    route("/late/v1/check", ex -> {
      answering.incrementAndGet();
      send(ex, 200, SignupCheckTest.answer("block").toString());
    });
    // Ignores the interrupt and returns after 2 s, past the 1.5 s deadline.
    CloseableHttpClient client =
        keycloakLike(
            HttpClients.custom()
                .disableRedirectHandling()
                .setRoutePlanner(
                    slowPlanner(() -> {
                      long until = System.nanoTime() + 2_000_000_000L;
                      while (System.nanoTime() < until) {
                        try {
                          Thread.sleep(50);
                        } catch (InterruptedException e) {
                          // keep going
                        }
                      }
                    })));
    Decision d = check(client, base + "/late");
    assertEquals("timeout", d.outcome());
    Thread.sleep(2500);
    assertEquals(0, answering.get(), "a call the registration gave up on still reached the server");
  }

  @Test
  void aBodySentSlowlyIsCutOffAtTheSameDeadlineAndItsConnectionClosed() throws InterruptedException {
    AtomicInteger answering = new AtomicInteger();
    AtomicInteger hungUp = new AtomicInteger();
    route("/trickle/v1/check", ex -> {
      answering.incrementAndGet();
      ex.sendResponseHeaders(200, 0);
      OutputStream out = ex.getResponseBody();
      try {
        for (int i = 0; i < 100; i++) {
          out.write(' ');
          out.flush();
          Thread.sleep(50);
        }
        out.write(SignupCheckTest.answer("block").toString().getBytes(StandardCharsets.UTF_8));
      } catch (IOException e) {
        hungUp.incrementAndGet();
      }
    });
    long t = System.nanoTime();
    Decision d = check("/trickle");
    long ms = (System.nanoTime() - t) / 1_000_000;
    assertFalse(d.refuse());
    assertEquals("timeout", d.outcome());
    assertTrue(ms < 2500, "gave up after " + ms + " ms");
    Thread.sleep(1500);
    assertEquals(1, answering.get());
    assertEquals(1, hungUp.get(), "a call the registration gave up on is still being answered");
  }

  @Test
  void aRedirectIsNotFollowedEvenByAClientThatFollowsRedirects() {
    // Keycloak 25's client follows redirects, and on 26 an admin can turn allow-redirects on.
    route("/target/v1/check", ex -> {
      redirectTargetHits.incrementAndGet();
      send(ex, 200, SignupCheckTest.answer("block").toString());
    });
    route("/moved/v1/check", ex -> {
      ex.getResponseHeaders().set("Location", base + "/target/v1/check");
      ex.getRequestBody().readAllBytes();
      ex.sendResponseHeaders(307, -1);
    });
    CloseableHttpClient following = keycloakLike(HttpClients.custom().setRedirectStrategy(LaxRedirectStrategy.INSTANCE));
    Decision d = check(following, base + "/moved");
    assertFalse(d.refuse());
    assertEquals("request_refused", d.outcome());
    assertEquals(307, d.status());
    assertEquals(0, redirectTargetHits.get());
  }

  @Test
  void anAnswerOverTheCapIsNoAnswer() {
    for (boolean withLength : new boolean[] {false, true}) {
      String path = withLength ? "/huge-length" : "/huge";
      route(path + "/v1/check", ex -> {
        String block = SignupCheckTest.answer("block").toString();
        byte[] head = (block.substring(0, block.length() - 1) + ",\"pad\":\"").getBytes(StandardCharsets.UTF_8);
        byte[] chunk = "x".repeat(8192).getBytes(StandardCharsets.UTF_8);
        byte[] tail = "\"}".getBytes(StandardCharsets.UTF_8);
        ex.sendResponseHeaders(200, withLength ? head.length + 20L * chunk.length + tail.length : 0);
        OutputStream out = ex.getResponseBody();
        out.write(head);
        for (int i = 0; i < 20; i++) out.write(chunk);
        out.write(tail);
      });
      Decision d = check(path);
      assertFalse(d.refuse());
      assertEquals("unexpected_answer", d.outcome(), path);
    }
  }

  @Test
  void aServerErrorAClosedPortAndNoClientLetTheSignupThrough() throws IOException {
    route("/broken/v1/check", ex -> send(ex, 500, "{\"error\":\"oops\"}"));
    assertEquals("server_error", check("/broken").outcome());

    int closedPort;
    try (ServerSocket s = new ServerSocket(0)) {
      closedPort = s.getLocalPort();
    }
    Decision d = check(keycloakLike(), "http://127.0.0.1:" + closedPort);
    assertFalse(d.refuse());
    assertEquals("network_error", d.outcome());

    Supplier<HttpClient> missing = () -> {
      throw new IllegalStateException("no provider");
    };
    assertEquals("network_error", check(missing, base + "/broken").outcome());
    assertEquals("network_error", check(() -> null, base + "/broken").outcome());
  }

  @Test
  void whenEveryPooledThreadIsBusyTheNextCallFailsAtOnce() throws Exception {
    route("/slow/v1/check", ex -> Thread.sleep(3000));
    callers.shutdownNow();
    callers = new ThreadPoolExecutor(0, 1, 30, TimeUnit.SECONDS, new SynchronousQueue<>());
    CloseableHttpClient client = keycloakLike();
    CompletableFuture<Decision> first = CompletableFuture.supplyAsync(() -> check(client, base + "/slow"));
    Thread.sleep(300);
    long t = System.nanoTime();
    Decision second = check(client, base + "/slow");
    long ms = (System.nanoTime() - t) / 1_000_000;
    assertEquals("network_error", second.outcome());
    assertTrue(ms < 200, "waited " + ms + " ms for a full pool");
    assertEquals("timeout", first.get(5, TimeUnit.SECONDS).outcome());
  }

  @Test
  void aCheckSentOverHttpsIsNeverSentTwiceByARetryingClient() throws Exception {
    // A server that reads the request and hangs up without answering, as a dropped connection looks to the client.
    AtomicInteger received = new AtomicInteger();
    try (ServerSocket socket = new ServerSocket(0, 50, java.net.InetAddress.getLoopbackAddress())) {
      Thread accepter = new Thread(() -> {
        while (!socket.isClosed()) {
          try (java.net.Socket s = socket.accept()) {
            java.io.InputStream in = s.getInputStream();
            StringBuilder seen = new StringBuilder();
            int c;
            while ((c = in.read()) != -1) {
              seen.append((char) c);
              if (seen.indexOf("\r\n\r\n") >= 0 && seen.charAt(seen.length() - 1) == '}') break;
            }
            received.incrementAndGet();
          } catch (IOException e) {
            // closed
          }
        }
      });
      accepter.setDaemon(true);
      accepter.start();
      // What Keycloak builds when an admin sets max-retries: it resends a request already sent.
      CloseableHttpClient retrying =
          HttpClients.custom().setRetryHandler(new org.apache.http.impl.client.DefaultHttpRequestRetryHandler(3, true)).build();
      clients.add(retrying);
      String url = "http://127.0.0.1:" + socket.getLocalPort() + "/v1/check";
      byte[] body = "{}".getBytes(StandardCharsets.UTF_8);

      assertFalse(HttpClientTransport.entity(body, true).isRepeatable());
      sendExpectingFailure(retrying, url, HttpClientTransport.entity(body, true));
      assertEquals(1, received.get(), "a check sent once must reach SignupBouncer once");

      // The same client resends a repeatable body: this is what the https body prevents.
      received.set(0);
      sendExpectingFailure(retrying, url, HttpClientTransport.entity(body, false));
      assertEquals(4, received.get());
    }
  }

  private static void sendExpectingFailure(CloseableHttpClient client, String url, org.apache.http.HttpEntity entity) {
    org.apache.http.client.methods.HttpPost post = new org.apache.http.client.methods.HttpPost(url);
    post.setEntity(entity);
    try {
      client.execute(post).close();
    } catch (IOException e) {
      return;
    }
    throw new AssertionError("the server never answers, so the call should fail");
  }
}
