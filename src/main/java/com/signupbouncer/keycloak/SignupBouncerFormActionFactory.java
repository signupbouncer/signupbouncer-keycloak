package com.signupbouncer.keycloak;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.authentication.FormAction;
import org.keycloak.authentication.FormActionFactory;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

/**
 * Registers the "SignupBouncer signup check" step for registration forms (META-INF/services). The step's settings
 * hold the API key and the challenge choice per realm. The server option base-url points every realm at another copy
 * of the API, for tests; only whoever starts Keycloak can set it, so a realm admin cannot send keys elsewhere.
 *
 * <p>Each check goes out through Keycloak's own HTTP client, taken from the session of the registration it checks, so
 * the outgoing proxy and truststore Keycloak was started with apply to it.
 */
public final class SignupBouncerFormActionFactory implements FormActionFactory {

  private static final Logger LOG = Logger.getLogger(SignupBouncerFormActionFactory.class);

  public static final String PROVIDER_ID = "signupbouncer";
  public static final String API_KEY = "apiKey";
  public static final String APP = "app";
  public static final String REFUSE_CHALLENGE = "refuseChallenge";
  public static final String SEND_IP = "sendIp";

  private static final AuthenticationExecutionModel.Requirement[] REQUIREMENTS = {
    AuthenticationExecutionModel.Requirement.REQUIRED, AuthenticationExecutionModel.Requirement.DISABLED
  };

  private volatile String baseUrl = SignupCheck.DEFAULT_BASE_URL;
  private volatile String userAgent = "signupbouncer-keycloak/dev";
  private final ExecutorService callers = HttpClientTransport.newCallPool();

  static String version() {
    String v = SignupBouncerFormActionFactory.class.getPackage().getImplementationVersion();
    return v == null ? "dev" : v;
  }

  @Override
  public void init(Config.Scope config) {
    String configured = config == null ? null : config.get("base-url");
    String base = SignupCheck.normalizeBaseUrl(configured);
    if (configured != null && !configured.isBlank()) {
      if (base.equals(SignupCheck.DEFAULT_BASE_URL)) {
        LOG.warnf("SignupBouncer: ignoring base-url, which is not an http(s) URL; using %s", base);
      } else {
        LOG.infof("SignupBouncer: checking signups against %s", base);
      }
    }
    baseUrl = base;
    userAgent = "signupbouncer-keycloak/" + version();
  }

  @Override
  public FormAction create(KeycloakSession session) {
    Transport transport =
        new HttpClientTransport(
            () -> session.getProvider(HttpClientProvider.class).getHttpClient(), callers, SignupCheck.MAX_ANSWER_BYTES);
    return new SignupBouncerFormAction(new SignupCheck(transport, baseUrl, SignupCheck.TIMEOUT, userAgent));
  }

  @Override
  public void postInit(KeycloakSessionFactory factory) {}

  @Override
  public void close() {
    callers.shutdownNow();
  }

  @Override
  public String getId() {
    return PROVIDER_ID;
  }

  @Override
  public String getDisplayType() {
    return "SignupBouncer signup check";
  }

  @Override
  public String getReferenceCategory() {
    return PROVIDER_ID;
  }

  @Override
  public String getHelpText() {
    return "Checks the email address and IP address of each new signup with SignupBouncer, and refuses the signups it"
        + " marks block. If SignupBouncer can't answer within 1.5 seconds, the signup goes through. A new SignupBouncer"
        + " app starts in shadow mode, so we log each signup on your dashboard's Checks tab and refuse nothing until"
        + " you switch the app to enforce mode on the Rules tab. If no signup appears there, look for a SignupBouncer"
        + " warning in Keycloak's log.";
  }

  @Override
  public boolean isConfigurable() {
    return true;
  }

  @Override
  public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
    return REQUIREMENTS;
  }

  @Override
  public boolean isUserSetupAllowed() {
    return false;
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    return ProviderConfigurationBuilder.create()
        .property()
        .name(API_KEY)
        .label("API key")
        .helpText(
            "The sb_live_... key you create on your app's Integration tab on the SignupBouncer dashboard. A wrong or"
                + " revoked key lets every signup through unchecked.")
        .type(ProviderConfigProperty.PASSWORD)
        .secret(true)
        .add()
        .property()
        .name(REFUSE_CHALLENGE)
        .label("Refuse signups marked challenge")
        .helpText(
            "A challenge is a signup SignupBouncer finds suspicious but not clear enough to refuse, such as the third"
                + " spelling of the same inbox within 7 days. Off: it goes through, with Keycloak's email verification"
                + " if the realm has it on. On: it's refused with the same message as a block, unless burst points"
                + " helped cause it.")
        .type(ProviderConfigProperty.BOOLEAN_TYPE)
        .defaultValue("false")
        .add()
        .property()
        .name(SEND_IP)
        .label("Send the visitor's IP address")
        .helpText(
            "Off: we check the email address only. Behind a proxy, leave it on only if you set Keycloak's"
                + " proxy-headers and proxy-trusted-addresses options and your proxy overwrites X-Forwarded-For."
                + " Otherwise every signup has the proxy's address, or the visitor can choose the address we check.")
        .type(ProviderConfigProperty.BOOLEAN_TYPE)
        .defaultValue("true")
        .add()
        .property()
        .name(APP)
        .label("App ID (older keys only)")
        .helpText(
            "Leave this empty unless your key shows \"all apps (older key)\" on the dashboard. Then paste the app_..."
                + " ID of the app to check. With a wrong ID, every signup goes through unchecked and Keycloak logs a"
                + " warning.")
        .type(ProviderConfigProperty.STRING_TYPE)
        .add()
        .build();
  }

  /** The step's settings, from its config. A missing config means no API key, so every signup goes through. */
  static SignupCheck.Settings settings(Map<String, String> config) {
    if (config == null) return new SignupCheck.Settings(null, null, false);
    return new SignupCheck.Settings(
        config.get(API_KEY), config.get(APP), "true".equalsIgnoreCase(config.get(REFUSE_CHALLENGE)));
  }

  /** On unless the admin turned it off. */
  static boolean sendIp(Map<String, String> config) {
    return config == null || !"false".equalsIgnoreCase(config.get(SEND_IP));
  }
}
