package com.signupbouncer.keycloak;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeoutException;
import java.util.regex.Pattern;

/**
 * The SignupBouncer check without any Keycloak code: building the request to POST /v1/check, the 1.5-second limit, and
 * turning the answer (or its absence) into a Decision. SignupBouncerFormAction is the thin Keycloak glue around it.
 *
 * <p>The rules match SignupBouncer's other integrations. Any failure lets the signup through: no API key, a timeout, a
 * network failure, a 5xx, a 429, a refused key (401), an account with no app (404), any other non-2xx answer, an
 * answer that is not complete, or an App ID setting too long to be an app ID (no call: the API would not know which app
 * it meant). Only a complete, consistent answer can refuse a signup: action "block", or "challenge"
 * when the realm chose to refuse those. An address over 320 characters is refused without a call, as in every other
 * SignupBouncer integration (no real address is that long).
 */
public final class SignupCheck {

  public static final String DEFAULT_BASE_URL = "https://signupbouncer.com";
  public static final String CHECK_PATH = "/v1/check";
  public static final Duration TIMEOUT = Duration.ofMillis(1500);
  /** A real answer is far smaller. A larger one is read as no answer. */
  public static final int MAX_ANSWER_BYTES = 65536;
  public static final int MAX_EMAIL_LENGTH = 320;
  /** The API reads at most this much of "app". A longer App ID setting is never an app ID (they're app_ and 24 hex). */
  public static final int MAX_APP_LENGTH = 64;
  /** Shown when an answer refuses a signup without a usable block_message. Also the API's own default. */
  public static final String DEFAULT_MESSAGE = "Please sign up with a permanent email address.";

  private static final Pattern ID_PATTERN = Pattern.compile("^[A-Za-z0-9._:-]{1,128}$");
  private static final Set<String> ACTIONS = Set.of("allow", "challenge", "block");
  /** Trailing text after the answer's object (a second object, junk) makes the whole answer unreadable. */
  private static final ObjectMapper JSON =
      new ObjectMapper().enable(com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_TRAILING_TOKENS);

  /**
   * SignupBouncer's velocity reasons (core/rules.ts, `velocity: true`): bursts of signups. They can make a signup a
   * challenge, never a refusal, so "Refuse signups marked challenge" doesn't apply to a challenge they helped cause,
   * exactly as the Supabase and Ory hooks treat their "Treat as block" setting.
   */
  static final Set<String> VELOCITY_REASONS =
      Set.of("burst_subnet", "burst_asn", "burst_inbox", "burst_pattern", "burst_domain");

  /** What the realm's admin set on the form action. */
  public record Settings(String apiKey, String app, boolean refuseChallenge) {}

  /** One registration: what the visitor typed and where they came from. Any field may be null. */
  public record Signup(String email, String ip, String userAgent, String attemptId) {}

  private final Transport transport;
  private final URI checkUri;
  private final Duration timeout;
  private final String userAgent;

  public SignupCheck(Transport transport, String baseUrl, Duration timeout, String userAgent) {
    this.transport = transport;
    this.checkUri = URI.create(normalizeBaseUrl(baseUrl) + CHECK_PATH);
    this.timeout = timeout;
    this.userAgent = userAgent;
  }

  /** The base URL without trailing slashes; the default when it is missing or not an http(s) URL. */
  public static String normalizeBaseUrl(String baseUrl) {
    if (baseUrl == null) return DEFAULT_BASE_URL;
    String b = baseUrl.trim().replaceAll("/+$", "");
    if (!b.matches("^https?://[^\\s/?#]+(/[^\\s?#]*)?$")) return DEFAULT_BASE_URL;
    return b;
  }

  /** Checks one signup. Never throws: every failure becomes a Decision that lets the signup through. */
  public Decision check(Settings settings, Signup signup) {
    String key = trimmed(settings == null ? null : settings.apiKey());
    if (key == null) return Decision.unchecked("no_api_key", null);
    String email = trimmed(signup.email());
    String ip = trimmed(signup.ip());
    if (email == null && ip == null) return Decision.unchecked("nothing_to_check", null);
    if (email != null && email.length() > MAX_EMAIL_LENGTH) {
      return new Decision(true, DEFAULT_MESSAGE, "email_too_long", null, null);
    }
    // Sent as typed, or not at all: a value the API can't read as an app id must not quietly become the account's
    // first app, where an older all-apps key would check and count the signup against that app's rules.
    String app = trimmed(settings.app());
    if (app != null && app.length() > MAX_APP_LENGTH) return Decision.unchecked("bad_app_id", null);
    byte[] body;
    try {
      body = requestBody(settings, signup, email, ip);
    } catch (IOException e) {
      return Decision.unchecked("unexpected_answer", null);
    }
    Map<String, String> headers = new LinkedHashMap<>();
    headers.put("Authorization", "Bearer " + key);
    headers.put("Content-Type", "application/json");
    headers.put("Accept", "application/json");
    headers.put("User-Agent", userAgent);
    Transport.Answer answer;
    try {
      answer = transport.post(checkUri, headers, body, timeout);
    } catch (TimeoutException e) {
      return Decision.unchecked("timeout", null);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      return Decision.unchecked("timeout", null);
    } catch (IOException | RuntimeException e) {
      return Decision.unchecked("network_error", null);
    }
    if (answer == null) return Decision.unchecked("unexpected_answer", null);
    return decide(answer.status(), answer.body(), settings.refuseChallenge());
  }

  static byte[] requestBody(Settings settings, Signup signup, String email, String ip) throws IOException {
    ObjectNode body = JSON.createObjectNode();
    if (email != null) body.put("email", email);
    if (ip != null && ip.length() <= 64) body.put("ip", ip);
    String ua = trimmed(signup.userAgent());
    if (ua != null) body.put("user_agent", ua.length() > 512 ? ua.substring(0, 512) : ua);
    String app = trimmed(settings.app());
    // Only needed with an older all-apps key. Sent as typed: a wrong id gets 404 unknown_app, which fails open and is
    // logged, rather than silently checking the account's first app. check() never gets here with a longer one.
    if (app != null) body.put("app", app);
    // Only for a signup without an email: it tells SignupBouncer that repeated submits of one registration are one
    // signup. With an email, the address does that, and a stable id would count a fresh attempt as a new signup.
    String attemptId = trimmed(signup.attemptId());
    if (email == null && attemptId != null && ID_PATTERN.matcher(attemptId).matches()) {
      body.put("attempt_id", attemptId);
    }
    return JSON.writeValueAsBytes(body);
  }

  /** Turns SignupBouncer's HTTP answer into a Decision. */
  public static Decision decide(int status, byte[] bytes, boolean refuseChallenge) {
    if (status == 401) return Decision.unchecked("key_refused", status);
    JsonNode body = parse(bytes);
    if (status == 404 && body != null && "unknown_app".equals(text(body.get("error")))) {
      return Decision.unchecked("no_app", status);
    }
    if (status >= 500) return Decision.unchecked("server_error", status);
    if (status == 429) return Decision.unchecked("rate_limited", status);
    if (status < 200 || status > 299) return Decision.unchecked("request_refused", status);
    if (body == null || !isCompleteAnswer(body)) return Decision.unchecked("unexpected_answer", status);
    String checkId = body.get("check_id").asText();
    // A complete answer that checked nothing: our side failed, or the account is past its allowance or cap. The API
    // already says allow in both cases.
    if (body.has("error")) return new Decision(false, null, "internal_error", checkId, status);
    if (body.get("quota_exceeded").asBoolean()) return new Decision(false, null, "quota_exceeded", checkId, status);
    String action = body.get("action").asText();
    switch (action) {
      case "block":
        return new Decision(true, messageOf(body), "block", checkId, status);
      case "challenge":
        return refuseChallenge && !velocityChallenge(body)
            ? new Decision(true, messageOf(body), "challenge_refused", checkId, status)
            : new Decision(false, null, "challenge_allowed", checkId, status);
      default:
        return new Decision(false, null, "allow", checkId, status);
    }
  }

  /**
   * Whether velocity points helped make this challenge, so it must go through even when the realm refuses challenges.
   * The hooks' rule (api/src/routes/machine.ts): a velocity reason with points, and no check the app set to "Always
   * challenge" (a reason with "setting": "challenge"), which stands on its own.
   */
  static boolean velocityChallenge(JsonNode body) {
    boolean velocity = false;
    for (JsonNode r : body.get("reasons")) {
      if ("challenge".equals(text(r.get("setting")))) return false;
      String code = text(r.get("code"));
      if (r.get("points").asDouble() > 0 && code != null && (VELOCITY_REASONS.contains(code) || code.startsWith("burst_"))) {
        velocity = true;
      }
    }
    return velocity;
  }

  /** The JSON object in bytes, or null for anything else (no body, bad UTF-8, not JSON, not an object). */
  static JsonNode parse(byte[] bytes) {
    if (bytes == null || bytes.length == 0) return null;
    try {
      // Strict UTF-8: a malformed byte is a failed check, not a replacement character.
      String text =
          StandardCharsets.UTF_8
              .newDecoder()
              .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
              .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
              .decode(java.nio.ByteBuffer.wrap(bytes))
              .toString();
      JsonNode node = JSON.readTree(text);
      return node != null && node.isObject() ? node : null;
    } catch (IOException | RuntimeException e) {
      return null;
    }
  }

  /**
   * Whether a 200 answer has every field the API always sends, with the right types. A challenge or block must also
   * agree with itself: "verdict" the same as "action", enforce mode, nothing over quota and no error. Anything else is
   * read as no answer, so a broken answer can never refuse a signup.
   */
  static boolean isCompleteAnswer(JsonNode v) {
    if (!v.isObject()) return false;
    String action = text(v.get("action"));
    String verdict = text(v.get("verdict"));
    String mode = text(v.get("mode"));
    if (action == null || !ACTIONS.contains(action)) return false;
    if (verdict == null || !ACTIONS.contains(verdict)) return false;
    if (!"shadow".equals(mode) && !"enforce".equals(mode)) return false;
    if (!isBoolean(v.get("quota_exceeded"))) return false;
    if (!isNumber(v.get("score")) || text(v.get("check_id")) == null || !isNumber(v.get("latency_ms"))) {
      return false;
    }
    JsonNode reasons = v.get("reasons");
    if (reasons == null || !reasons.isArray()) return false;
    for (JsonNode r : reasons) {
      if (!r.isObject()
          || text(r.get("code")) == null
          || text(r.get("detail")) == null
          || !isNumber(r.get("points"))
          || text(r.get("tier")) == null) {
        return false;
      }
    }
    JsonNode shadow = v.get("shadow");
    if (shadow == null || !shadow.isArray()) return false;
    for (JsonNode r : shadow) {
      if (!r.isObject() || text(r.get("code")) == null || text(r.get("detail")) == null || text(r.get("tier")) == null) {
        return false;
      }
    }
    JsonNode n = v.get("normalized");
    if (n == null || !n.isObject() || !isNullableText(n.get("provider")) || !isNumber(n.get("repeat_signups_7d"))) {
      return false;
    }
    JsonNode net = v.get("network");
    if (net == null) return false;
    if (!net.isNull()) {
      if (!net.isObject()) return false;
      JsonNode asn = net.get("asn");
      if (asn == null || !(asn.isNull() || isNumber(asn))) return false;
      if (!isNullableText(net.get("asn_org")) || !isNullableText(net.get("label"))) return false;
      if (text(net.get("prefix")) == null) return false;
      JsonNode kinds = net.get("kinds");
      if (kinds == null || !kinds.isArray()) return false;
      for (JsonNode k : kinds) if (!k.isTextual()) return false;
    }
    if (!"allow".equals(action)) {
      if (!action.equals(verdict)
          || !"enforce".equals(mode)
          || v.get("quota_exceeded").asBoolean()
          || v.has("error")) {
        return false;
      }
    }
    return true;
  }

  /** The block_message SignupBouncer sent (the Rules tab's, or its default worded for the reason), or ours. */
  static String messageOf(JsonNode body) {
    String m = text(body.get("block_message"));
    return m != null && !m.isBlank() && m.length() <= 500 ? m : DEFAULT_MESSAGE;
  }

  private static String text(JsonNode n) {
    return n != null && n.isTextual() ? n.asText() : null;
  }

  private static boolean isNullableText(JsonNode n) {
    return n != null && (n.isNull() || n.isTextual());
  }

  private static boolean isNumber(JsonNode n) {
    return n != null && n.isNumber() && Double.isFinite(n.asDouble());
  }

  private static boolean isBoolean(JsonNode n) {
    return n != null && n.isBoolean();
  }

  private static String trimmed(String s) {
    if (s == null) return null;
    String t = s.trim();
    return t.isEmpty() ? null : t;
  }
}
