package com.signupbouncer.keycloak;

import java.io.IOException;
import java.net.URI;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.TimeoutException;

/** Sends one POST and returns the status and body. Keycloak's checks use HttpClientTransport; the tests pass fakes. */
public interface Transport {

  /** An HTTP answer. body is null when it was larger than the cap. */
  record Answer(int status, byte[] body) {}

  /**
   * Posts body to uri with the given headers. Must return or throw within the deadline, which covers connecting,
   * sending and reading the whole answer. Must not follow redirects.
   */
  Answer post(URI uri, Map<String, String> headers, byte[] body, Duration deadline)
      throws IOException, TimeoutException, InterruptedException;
}
