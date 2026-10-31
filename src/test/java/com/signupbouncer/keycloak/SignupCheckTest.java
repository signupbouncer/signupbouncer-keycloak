package com.signupbouncer.keycloak;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeoutException;
import org.junit.jupiter.api.Test;

/** The decision logic, with a fake transport: every way to fail open, block, and challenge both ways. */
class SignupCheckTest {

  private static final ObjectMapper JSON = new ObjectMapper();
  private static final SignupCheck.Settings KEY = new SignupCheck.Settings("sb_live_test", null, false);
  private static final SignupCheck.Settings KEY_REFUSE = new SignupCheck.Settings("sb_live_test", null, true);
  private static final SignupCheck.Signup SIGNUP =
      new SignupCheck.Signup("ann@example.com", "203.0.113.7", "Mozilla/5.0", "kc:abc");

  /** A fake transport that answers one thing and records each request. */
  static final class Fake implements Transport {
    interface Reply {
      Answer reply() throws IOException, TimeoutException, InterruptedException;
    }

    final Reply reply;
    final List<Map<String, String>> headers = new ArrayList<>();
    final List<JsonNode> bodies = new ArrayList<>();
    final List<URI> uris = new ArrayList<>();
    final List<Duration> deadlines = new ArrayList<>();

    Fake(Reply reply) {
      this.reply = reply;
    }

    static Fake answering(int status, String body) {
      return new Fake(() -> new Answer(status, body == null ? null : body.getBytes(StandardCharsets.UTF_8)));
    }

    @Override
    public Answer post(URI uri, Map<String, String> h, byte[] body, Duration deadline)
        throws IOException, TimeoutException, InterruptedException {
      uris.add(uri);
      headers.add(h);
      bodies.add(JSON.readTree(body));
      deadlines.add(deadline);
      return reply.reply();
    }
  }

  /** A complete enforce-mode answer with the given action, as /v1/check sends it. */
  static ObjectNode answer(String action) {
    ObjectNode a = JSON.createObjectNode();
    a.put("verdict", action);
    a.put("action", action);
    a.put("mode", "enforce");
    a.put("score", "allow".equals(action) ? 0 : 100);
    a.put("check_id", "chk_123");
    ObjectNode reason = a.putArray("reasons").addObject();
    reason.put("code", "disposable_domain");
    reason.put("detail", "on the list");
    reason.put("points", 100);
    reason.put("tier", "free");
    ObjectNode normalized = a.putObject("normalized");
    normalized.putNull("provider");
    normalized.put("repeat_signups_7d", 0);
    ObjectNode network = a.putObject("network");
    network.put("asn", 64500);
    network.put("asn_org", "Example");
    network.putArray("kinds").add("datacenter");
    network.putNull("label");
    network.put("prefix", "203.0.113.0/24");
    a.putArray("shadow");
    a.put("latency_ms", 2.1);
    a.put("quota_exceeded", false);
    if (!"allow".equals(action)) a.put("block_message", "Please use your work address.");
    return a;
  }

  static Decision run(SignupCheck.Settings settings, Fake fake) {
    return new SignupCheck(fake, "http://127.0.0.1:1", Duration.ofMillis(1500), "signupbouncer-keycloak/test")
        .check(settings, SIGNUP);
  }

  static Decision run(Fake fake) {
    return run(KEY, fake);
  }

  // ---- The request ------------------------------------------------------------------------------------------------

  @Test
  void sendsTheSignupWithTheKeyAndOurUserAgent() {
    Fake fake = Fake.answering(200, answer("allow").toString());
    run(fake);
    assertEquals(URI.create("http://127.0.0.1:1/v1/check"), fake.uris.get(0));
    assertEquals("Bearer sb_live_test", fake.headers.get(0).get("Authorization"));
    assertEquals("application/json", fake.headers.get(0).get("Content-Type"));
    assertEquals("signupbouncer-keycloak/test", fake.headers.get(0).get("User-Agent"));
    JsonNode body = fake.bodies.get(0);
    assertEquals("ann@example.com", body.get("email").asText());
    assertEquals("203.0.113.7", body.get("ip").asText());
    assertEquals("Mozilla/5.0", body.get("user_agent").asText());
    assertFalse(body.has("app"), "the key sets the app");
    assertFalse(body.has("attempt_id"), "with an email, the address identifies the signup");
    assertEquals(Duration.ofMillis(1500), fake.deadlines.get(0));
  }

  @Test
  void sendsTheAppOnlyWhenSetAndAnAttemptIdOnlyWithoutAnEmail() {
    Fake fake = Fake.answering(200, answer("allow").toString());
    SignupCheck check = new SignupCheck(fake, "https://example.test/", Duration.ofMillis(1500), "ua");
    check.check(
        new SignupCheck.Settings("k", " app_0123456789abcdef01234567 ", false),
        new SignupCheck.Signup("  ", "203.0.113.7", null, "kc:abc-_1"));
    JsonNode body = fake.bodies.get(0);
    assertEquals(URI.create("https://example.test/v1/check"), fake.uris.get(0));
    assertEquals("app_0123456789abcdef01234567", body.get("app").asText());
    assertFalse(body.has("email"));
    assertFalse(body.has("user_agent"));
    assertEquals("kc:abc-_1", body.get("attempt_id").asText());
  }

  @Test
  void anAppIdTooLongToBeOneMakesNoCallRatherThanCheckingAnotherApp() {
    Fake fake = Fake.answering(200, answer("block").toString());
    String pasted = "https://signupbouncer.com/app/integration?app=app_0123456789abcdef01234567#keys";
    Decision d = run(new SignupCheck.Settings("sb_live_test", pasted, true), fake);
    assertFalse(d.refuse());
    assertEquals("bad_app_id", d.outcome());
    assertFalse(d.checked());
    assertTrue(fake.uris.isEmpty(), "no call, so the account's first app isn't checked instead");

    // Up to the API's limit, any other value goes as typed, and a wrong one comes back 404 unknown_app.
    String wrong = "x".repeat(SignupCheck.MAX_APP_LENGTH);
    Fake notFound = Fake.answering(404, "{\"error\":\"unknown_app\",\"message\":\"no app\"}");
    Decision d2 = run(new SignupCheck.Settings("sb_live_test", " " + wrong + " ", true), notFound);
    assertEquals(wrong, notFound.bodies.get(0).get("app").asText());
    assertEquals("no_app", d2.outcome());
    assertFalse(d2.refuse());
  }

  @Test
  void cutsALongUserAgent() {
    Fake fake = Fake.answering(200, answer("allow").toString());
    new SignupCheck(fake, null, Duration.ofMillis(1500), "ua")
        .check(KEY, new SignupCheck.Signup("ann@example.com", null, "x".repeat(2000), null));
    assertEquals(512, fake.bodies.get(0).get("user_agent").asText().length());
    assertEquals(URI.create("https://signupbouncer.com/v1/check"), fake.uris.get(0));
  }

  @Test
  void aBaseUrlThatIsNotHttpFallsBackToSignupBouncer() {
    assertEquals("https://signupbouncer.com", SignupCheck.normalizeBaseUrl("file:///etc/passwd"));
    assertEquals("https://signupbouncer.com", SignupCheck.normalizeBaseUrl(" "));
    assertEquals("http://127.0.0.1:8097", SignupCheck.normalizeBaseUrl("http://127.0.0.1:8097//"));
  }

  // ---- Allow, block, challenge ------------------------------------------------------------------------------------

  @Test
  void allowLetsTheSignupThrough() {
    Decision d = run(Fake.answering(200, answer("allow").toString()));
    assertFalse(d.refuse());
    assertEquals("allow", d.outcome());
    assertEquals("chk_123", d.checkId());
    assertTrue(d.checked());
  }

  @Test
  void blockRefusesWithSignupBouncersMessage() {
    Decision d = run(Fake.answering(200, answer("block").toString()));
    assertTrue(d.refuse());
    assertEquals("block", d.outcome());
    assertEquals("Please use your work address.", d.message());
    assertEquals("chk_123", d.checkId());
  }

  @Test
  void blockWithoutAUsableMessageUsesTheDefault() {
    ObjectNode a = answer("block");
    a.remove("block_message");
    assertEquals(SignupCheck.DEFAULT_MESSAGE, run(Fake.answering(200, a.toString())).message());
    a.put("block_message", "   ");
    assertEquals(SignupCheck.DEFAULT_MESSAGE, run(Fake.answering(200, a.toString())).message());
    a.put("block_message", "x".repeat(501));
    assertEquals(SignupCheck.DEFAULT_MESSAGE, run(Fake.answering(200, a.toString())).message());
    a.put("block_message", 42);
    assertEquals(SignupCheck.DEFAULT_MESSAGE, run(Fake.answering(200, a.toString())).message());
  }

  @Test
  void challengeGoesThroughByDefault() {
    Decision d = run(Fake.answering(200, answer("challenge").toString()));
    assertFalse(d.refuse());
    assertEquals("challenge_allowed", d.outcome());
    assertTrue(d.checked());
  }

  @Test
  void challengeIsRefusedWhenTheRealmChoseThat() {
    Decision d = run(KEY_REFUSE, Fake.answering(200, answer("challenge").toString()));
    assertTrue(d.refuse());
    assertEquals("challenge_refused", d.outcome());
    assertEquals("Please use your work address.", d.message());
  }

  /** A challenge answer whose reasons are the given (code, points, setting) triples. */
  static ObjectNode challengeWith(Object[]... reasons) {
    ObjectNode a = answer("challenge");
    var list = a.putArray("reasons");
    for (Object[] r : reasons) {
      ObjectNode o = list.addObject();
      o.put("code", (String) r[0]);
      o.put("detail", "d");
      o.put("points", (Integer) r[1]);
      o.put("tier", "pro");
      if (r.length > 2) o.put("setting", (String) r[2]);
    }
    return a;
  }

  @Test
  void aChallengeThatBurstPointsHelpedCauseGoesThroughEvenWhenRefusingChallenges() {
    // As in the Supabase and Ory hooks: velocity points can make a challenge, never a refusal.
    for (String code : SignupCheck.VELOCITY_REASONS) {
      Decision d = run(KEY_REFUSE, Fake.answering(200, challengeWith(new Object[] {code, 25}, new Object[] {"datacenter_ip", 40}).toString()));
      assertFalse(d.refuse(), code);
      assertEquals("challenge_allowed", d.outcome(), code);
    }
  }

  @Test
  void aChallengeWithoutBurstPointsIsRefusedWhenRefusingChallenges() {
    // A burst reason with 0 points (it lost to another reason) doesn't count.
    Decision d = run(KEY_REFUSE, Fake.answering(200, challengeWith(new Object[] {"repeat_inbox", 40}, new Object[] {"burst_inbox", 0}).toString()));
    assertTrue(d.refuse());
    assertEquals("challenge_refused", d.outcome());
  }

  @Test
  void anAlwaysChallengeSettingStandsWithBurstPointsBesideIt() {
    Decision d =
        run(KEY_REFUSE, Fake.answering(200, challengeWith(new Object[] {"vpn_ip", 0, "challenge"}, new Object[] {"burst_subnet", 25}).toString()));
    assertTrue(d.refuse());
    assertEquals("challenge_refused", d.outcome());
  }

  @Test
  void shadowModeAnswersAllow() {
    ObjectNode a = answer("allow");
    a.put("verdict", "block");
    a.put("mode", "shadow");
    Decision d = run(KEY_REFUSE, Fake.answering(200, a.toString()));
    assertFalse(d.refuse());
    assertEquals("allow", d.outcome());
  }

  @Test
  void anAddressOver320CharactersIsRefusedWithoutACall() {
    Fake fake = Fake.answering(200, answer("allow").toString());
    Decision d =
        new SignupCheck(fake, null, Duration.ofMillis(1500), "ua")
            .check(KEY, new SignupCheck.Signup("a".repeat(310) + "@example.com", null, null, null));
    assertTrue(d.refuse());
    assertEquals("email_too_long", d.outcome());
    assertTrue(fake.uris.isEmpty());
  }

  // ---- Fail open --------------------------------------------------------------------------------------------------

  @Test
  void noKeyMakesNoCall() {
    Fake fake = Fake.answering(200, answer("block").toString());
    for (SignupCheck.Settings s :
        new SignupCheck.Settings[] {null, new SignupCheck.Settings(null, null, true), new SignupCheck.Settings(" ", null, true)}) {
      Decision d = run(s, fake);
      assertFalse(d.refuse());
      assertEquals("no_api_key", d.outcome());
      assertFalse(d.checked());
    }
    assertTrue(fake.uris.isEmpty());
  }

  @Test
  void nothingToCheckMakesNoCall() {
    Fake fake = Fake.answering(200, answer("block").toString());
    Decision d =
        new SignupCheck(fake, null, Duration.ofMillis(1500), "ua").check(KEY, new SignupCheck.Signup(null, " ", "x", "kc:1"));
    assertFalse(d.refuse());
    assertEquals("nothing_to_check", d.outcome());
    assertTrue(fake.uris.isEmpty());
  }

  @Test
  void timeoutNetworkErrorAndInterruptLetTheSignupThrough() {
    assertEquals("timeout", run(new Fake(() -> {
      throw new TimeoutException();
    })).outcome());
    assertEquals("network_error", run(new Fake(() -> {
      throw new IOException("connection refused");
    })).outcome());
    assertEquals("network_error", run(new Fake(() -> {
      throw new IllegalStateException("bug");
    })).outcome());
    Decision interrupted = run(new Fake(() -> {
      throw new InterruptedException();
    }));
    assertEquals("timeout", interrupted.outcome());
    assertFalse(interrupted.refuse());
    assertTrue(Thread.interrupted(), "the interrupt flag is restored");
  }

  @Test
  void errorStatusesLetTheSignupThrough() {
    String[][] cases = {
      {"401", "{\"error\":\"invalid_api_key\",\"message\":\"wrong\"}", "key_refused"},
      {"404", "{\"error\":\"unknown_app\",\"message\":\"no app\"}", "no_app"},
      {"404", "{\"error\":\"not_found\"}", "request_refused"},
      {"403", "{\"error\":\"app_mismatch\"}", "request_refused"},
      {"400", "{\"error\":\"invalid_body\"}", "request_refused"},
      {"413", "", "request_refused"},
      {"429", "", "rate_limited"},
      {"500", answer("block").toString(), "server_error"},
      {"503", "<html>down</html>", "server_error"},
      {"302", "", "request_refused"},
      {"204", "", "unexpected_answer"},
    };
    for (String[] c : cases) {
      Decision d = run(KEY_REFUSE, Fake.answering(Integer.parseInt(c[0]), c[1]));
      assertFalse(d.refuse(), c[0] + " " + c[1]);
      assertEquals(c[2], d.outcome(), c[0] + " " + c[1]);
      assertEquals(Integer.parseInt(c[0]), d.status());
      assertNull(d.message());
    }
  }

  @Test
  void ourOwnFailureAndQuotaAnswersAllow() {
    ObjectNode error = answer("allow");
    error.put("error", "internal_error");
    assertEquals("internal_error", run(Fake.answering(200, error.toString())).outcome());
    ObjectNode quota = answer("allow");
    quota.put("quota_exceeded", true);
    Decision d = run(Fake.answering(200, quota.toString()));
    assertEquals("quota_exceeded", d.outcome());
    assertFalse(d.refuse());
    assertFalse(d.checked());
  }

  @Test
  void malformedAnswersLetTheSignupThrough() {
    List<String> bodies = new ArrayList<>();
    bodies.add(null);
    bodies.add("");
    bodies.add("not json");
    bodies.add("[]");
    bodies.add("\"block\"");
    bodies.add("{\"action\":\"block\"}");
    bodies.add("{\"action\":\"block\",\"verdict\":\"block\",\"mode\":\"enforce\"}");
    // Each field the API always sends, missing or of the wrong type, on an otherwise complete block.
    String[] fields = {
      "verdict", "action", "mode", "score", "check_id", "reasons", "normalized", "network", "shadow", "latency_ms",
      "quota_exceeded"
    };
    for (String f : fields) {
      ObjectNode missing = answer("block");
      missing.remove(f);
      bodies.add(missing.toString());
      ObjectNode wrong = answer("block");
      if (List.of("verdict", "action", "mode", "check_id").contains(f)) {
        wrong.put(f, 1);
      } else {
        wrong.put(f, "1");
      }
      bodies.add(wrong.toString());
    }
    ObjectNode badReason = answer("block");
    ((ObjectNode) badReason.get("reasons").get(0)).put("points", "100");
    bodies.add(badReason.toString());
    ObjectNode badShadow = answer("block");
    badShadow.withArray("shadow").addObject().put("code", "datacenter_ip");
    bodies.add(badShadow.toString());
    ObjectNode badNetwork = answer("block");
    ((ObjectNode) badNetwork.get("network")).putArray("kinds").add(7);
    bodies.add(badNetwork.toString());
    ObjectNode badNormalized = answer("block");
    ((ObjectNode) badNormalized.get("normalized")).put("provider", 3);
    bodies.add(badNormalized.toString());
    ObjectNode unknownAction = answer("block");
    unknownAction.put("action", "deny");
    unknownAction.put("verdict", "deny");
    bodies.add(unknownAction.toString());
    // Inconsistent refusals: a block that disagrees with itself never refuses.
    ObjectNode verdictDiffers = answer("block");
    verdictDiffers.put("verdict", "challenge");
    bodies.add(verdictDiffers.toString());
    ObjectNode shadowBlock = answer("block");
    shadowBlock.put("mode", "shadow");
    bodies.add(shadowBlock.toString());
    ObjectNode quotaBlock = answer("block");
    quotaBlock.put("quota_exceeded", true);
    bodies.add(quotaBlock.toString());
    ObjectNode errorBlock = answer("block");
    errorBlock.put("error", "internal_error");
    bodies.add(errorBlock.toString());
    ObjectNode errorChallenge = answer("challenge");
    errorChallenge.put("error", "internal_error");
    bodies.add(errorChallenge.toString());

    for (String body : bodies) {
      Decision d = run(KEY_REFUSE, Fake.answering(200, body));
      assertFalse(d.refuse(), "refused on: " + body);
      assertEquals("unexpected_answer", d.outcome(), "outcome for: " + body);
    }
  }

  @Test
  void anAnswerWithAnythingAfterItsObjectLetsTheSignupThrough() {
    String block = answer("block").toString();
    for (String body : new String[] {block + " junk", block + "{}", block + block, block + "]"}) {
      Decision d = run(KEY_REFUSE, Fake.answering(200, body));
      assertFalse(d.refuse(), body);
      assertEquals("unexpected_answer", d.outcome());
    }
    assertTrue(run(KEY_REFUSE, Fake.answering(200, block + "\n  ")).refuse(), "trailing whitespace is fine");
  }

  @Test
  void anAnswerOverTheCapOrWithBadUtf8LetsTheSignupThrough() {
    assertEquals("unexpected_answer", run(KEY_REFUSE, new Fake(() -> new Transport.Answer(200, null))).outcome());
    byte[] bad = answer("block").toString().replace("Please", "Pléase").getBytes(StandardCharsets.ISO_8859_1);
    assertEquals("unexpected_answer", run(KEY_REFUSE, new Fake(() -> new Transport.Answer(200, bad))).outcome());
  }

  @Test
  void aNullNetworkAndExtraFieldsAreFine() {
    ObjectNode a = answer("block");
    a.putNull("network");
    a.put("suggestion", "ann@gmail.com");
    a.put("why_url", "https://signupbouncer.com/why/example.com");
    ((ObjectNode) a.get("reasons").get(0)).put("setting", "block");
    Decision d = run(Fake.answering(200, a.toString()));
    assertTrue(d.refuse());
    assertEquals("block", d.outcome());
  }

  @Test
  void settingsFromTheStepsConfig() {
    SignupCheck.Settings none = SignupBouncerFormActionFactory.settings(null);
    assertNull(none.apiKey());
    assertFalse(none.refuseChallenge());
    SignupCheck.Settings s =
        SignupBouncerFormActionFactory.settings(Map.of("apiKey", "sb_live_x", "refuseChallenge", "true", "app", "app_1"));
    assertEquals("sb_live_x", s.apiKey());
    assertEquals("app_1", s.app());
    assertTrue(s.refuseChallenge());
    assertFalse(SignupBouncerFormActionFactory.settings(Map.of("refuseChallenge", "yes")).refuseChallenge());
    assertTrue(SignupBouncerFormActionFactory.sendIp(null));
    assertTrue(SignupBouncerFormActionFactory.sendIp(Map.of()));
    assertFalse(SignupBouncerFormActionFactory.sendIp(Map.of("sendIp", "false")));
  }
}
