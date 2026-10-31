package com.signupbouncer.keycloak;

/**
 * What to do with one registration, and why.
 *
 * @param refuse  true only when SignupBouncer gave a complete answer that refuses the signup
 * @param message the text to show on the email field when refusing; null otherwise
 * @param outcome why: "allow", "block", "challenge_allowed", "challenge_refused" when SignupBouncer checked the
 *                signup, or the reason it was not checked ("timeout", "key_refused", ...). Safe to log: it never
 *                holds the key, the address or response text.
 * @param checkId SignupBouncer's id for the check ("chk_..."), when it answered with one
 * @param status  the HTTP status SignupBouncer answered with, when there was one
 */
public record Decision(boolean refuse, String message, String outcome, String checkId, Integer status) {

  /** The signup goes through without a usable answer from SignupBouncer. */
  static Decision unchecked(String outcome, Integer status) {
    return new Decision(false, null, outcome, null, status);
  }

  /** Whether SignupBouncer scored this signup (as opposed to letting it through unchecked). */
  public boolean checked() {
    return switch (outcome) {
      case "allow", "block", "challenge_allowed", "challenge_refused" -> true;
      default -> false;
    };
  }
}
