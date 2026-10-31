package com.signupbouncer.keycloak;

import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import java.util.List;
import java.util.Map;
import org.jboss.logging.Logger;
import org.keycloak.authentication.FormAction;
import org.keycloak.authentication.FormContext;
import org.keycloak.authentication.ValidationContext;
import org.keycloak.events.Errors;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.userprofile.UserProfile;
import org.keycloak.userprofile.UserProfileContext;
import org.keycloak.userprofile.UserProfileProvider;

/**
 * The registration form step. When someone submits the registration form, it sends the email address, the visitor's
 * IP address and User-Agent to SignupBouncer and refuses the signup only when SignupBouncer says block (or challenge,
 * if the realm chose to refuse those). Any failure lets the signup through and logs why.
 *
 * <p>Keycloak runs every step of the form on each submit, even when another step finds an error, so each submit is
 * one check. Every path that does not refuse calls context.success(): a form step that does neither leaves the form
 * on screen with no message.
 */
public final class SignupBouncerFormAction implements FormAction {

  private static final Logger LOG = Logger.getLogger(SignupBouncerFormAction.class);

  /** The message key on the email field. A realm overrides its text under Realm settings, Localization. */
  public static final String MESSAGE_KEY = "signupbouncerRefused";

  static final String EMAIL_FIELD = "email";

  private final SignupCheck check;

  SignupBouncerFormAction(SignupCheck check) {
    this.check = check;
  }

  @Override
  public void validate(ValidationContext context) {
    MultivaluedMap<String, String> form = context.getHttpRequest().getDecodedFormParameters();
    AuthenticatorConfigModel configModel = context.getAuthenticatorConfig();
    Map<String, String> config = configModel == null ? null : configModel.getConfig();
    SignupCheck.Settings settings = SignupBouncerFormActionFactory.settings(config);
    boolean sendIp = SignupBouncerFormActionFactory.sendIp(config);

    String ip = sendIp && context.getConnection() != null ? context.getConnection().getRemoteAddr() : null;
    String userAgent = context.getHttpRequest().getHttpHeaders().getHeaderString("User-Agent");
    String attemptId = attemptId(context);
    String email = registrationEmail(context, form);

    Decision decision;
    try {
      decision = check.check(settings, new SignupCheck.Signup(email, ip, userAgent, attemptId));
    } catch (RuntimeException e) {
      // SignupCheck never throws; this keeps that promise even if a bug slips in.
      decision = Decision.unchecked("internal_error", null);
    }
    log(context.getRealm(), decision);

    if (decision.checkId() != null) context.getEvent().detail("signupbouncer_check_id", decision.checkId());
    context.getEvent().detail("signupbouncer_outcome", decision.outcome());

    if (!decision.refuse()) {
      context.success();
      return;
    }
    context.error(Errors.INVALID_REGISTRATION);
    // The default text of signupbouncerRefused is "{0}": SignupBouncer's message, which its Rules tab sets. A realm
    // override with its own words replaces it, in each language the realm has. Without an email address the refusal
    // came from the IP checks, and the form may have no email field to show it under, so it goes above the form.
    String field = email == null ? null : EMAIL_FIELD;
    context.validationError(form, List.of(new FormMessage(field, MESSAGE_KEY, decision.message())));
  }

  /**
   * The email address the account will get, read the way Keycloak's own "Registration User Profile Creation" step
   * reads it: through the realm's user profile, which also accepts the field as user.attributes.email and normalizes
   * it. That step runs first and keeps its profile on the session; without it, we build one the same way. Reading the
   * raw "email" field instead would let a crafted form check one address and create an account with another.
   */
  static String registrationEmail(ValidationContext context, MultivaluedMap<String, String> form) {
    if (form == null) return null;
    KeycloakSession session = context.getSession();
    try {
      Object cached = session == null ? null : session.getAttribute("UP_REGISTER");
      UserProfile profile;
      if (cached instanceof UserProfile p) {
        profile = p;
      } else {
        MultivaluedHashMap<String, String> copy = new MultivaluedHashMap<>(form);
        copy.remove("password");
        copy.remove("password-confirm");
        copy.remove("g-recaptcha-response");
        profile = session.getProvider(UserProfileProvider.class).create(UserProfileContext.REGISTRATION, copy);
      }
      return blankToNull(profile.getAttributes().getFirst(UserModel.EMAIL));
    } catch (RuntimeException e) {
      // No profile: fall back to the field Keycloak's form sends.
      return blankToNull(form.getFirst(EMAIL_FIELD));
    }
  }

  private static String blankToNull(String s) {
    return s == null || s.isBlank() ? null : s;
  }

  /**
   * Identifies this registration for a signup without an email, so repeated sends of the same form count once. Each
   * browser tab has its own authentication session under the shared parent, so two tabs are two signups.
   */
  static String attemptId(ValidationContext context) {
    AuthenticationSessionModel auth = context.getAuthenticationSession();
    if (auth == null || auth.getParentSession() == null || auth.getTabId() == null) return null;
    return "kc:" + auth.getParentSession().getId() + "." + auth.getTabId();
  }

  /** One line per signup: the outcome, status and check id. Never the key, the address or response text. */
  private static void log(RealmModel realm, Decision d) {
    String realmName = realm == null ? "?" : realm.getName();
    String line =
        "SignupBouncer: realm="
            + realmName
            + " outcome="
            + d.outcome()
            + (d.status() == null ? "" : " status=" + d.status())
            + (d.checkId() == null ? "" : " check_id=" + d.checkId());
    switch (d.outcome()) {
      case "allow", "nothing_to_check" -> LOG.debug(line);
      case "block", "challenge_refused", "challenge_allowed", "email_too_long", "quota_exceeded" -> LOG.info(line);
      case "key_refused" -> LOG.warn(line + " (the API key is wrong, revoked or rotated; signups go through unchecked)");
      case "no_app" -> LOG.warn(line + " (no app on this account or for this App ID; signups go through unchecked)");
      case "bad_app_id" -> LOG.warn(
          line + " (the step's App ID setting is too long to be an app ID; signups go through unchecked until you fix it)");
      case "no_api_key" -> LOG.warn(line + " (no API key in the step's settings; signups go through unchecked)");
      case "request_refused" -> LOG.warn(line + " (check the App ID setting; signups go through unchecked)");
      default -> LOG.warn(line + " (signup went through unchecked)");
    }
  }

  @Override
  public void buildPage(FormContext context, LoginFormsProvider form) {}

  @Override
  public void success(FormContext context) {}

  @Override
  public boolean requiresUser() {
    return false;
  }

  @Override
  public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
    return true;
  }

  @Override
  public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {}

  @Override
  public void close() {}
}
