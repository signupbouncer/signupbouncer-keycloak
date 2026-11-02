# SignupBouncer for Keycloak

A registration step for Keycloak 26 that checks each new signup with [SignupBouncer](https://signupbouncer.com) before
Keycloak creates the account. It refuses throwaway email addresses, and refuses an inbox signed up again and again under
different spellings. Everyone else signs up as usual.

It works on SignupBouncer's Free plan. On the Free plan, you get 1,000 checks a month with no card. The extension is MIT
licensed and tested with Keycloak 26.8.1. It also passed our tests on Keycloak 25.0.6, which has no
`--proxy-trusted-addresses` option.

## What SignupBouncer checks

On every plan, including the Free plan:

- **Throwaway domains.** We rebuild our list of throwaway email domains every hour, so you don't refresh anything.
- **Throwaway mail servers.** We refuse a domain whose mail goes to a mail server that serves known throwaway domains,
  even when the domain isn't on any list yet.
- **Domains that can't receive mail.** A domain with no mail server can't get your verification email.
- **Repeat signups.** We treat Gmail dots and `+tags` as the same inbox, and count earlier signups of that inbox on your
  account over the last 7 days. With our default settings, we refuse the fifth spelling of an inbox within 7 days.

From the Starter plan, the signup's IP address counts toward the signup's score too: datacenter, VPN, Tor and hijacked
networks. On the Pro plan, bursts of signups count as well. The full list is on the
[docs page](https://signupbouncer.com/docs#reasons).

The Block Disposable Email extension checks addresses against a domain list it loads when Keycloak starts, and you
refresh the list through a REST endpoint. Alias Guard treats Gmail dots and `+tags` as the same inbox, and refuses a
second account for an inbox that already has one in the realm. SignupBouncer also checks where a domain's mail goes and
rebuilds its list every hour. From the Starter plan, it checks the IP address too.

## Install

1. [Sign up for SignupBouncer](https://signupbouncer.com/signup), then create an API key on your app's Integration tab.
   Copy the `sb_live_...` key. We show the key only once.
2. Download `keycloak-signupbouncer-0.1.0.jar` from the
   [latest release](https://github.com/signupbouncer/keycloak-signupbouncer/releases/latest), or build it (below).
3. Copy the jar into the `providers/` folder of your Keycloak 26 server. Run `bin/kc.sh build`, then restart Keycloak so
   it loads the step. A server you started with `start-dev` needs the restart only. In a container image, `COPY` the jar
   to `/opt/keycloak/providers/` before the build step.
4. In the admin console, open your realm, then Authentication. Duplicate the `registration` flow, for example as
   "registration with SignupBouncer".
5. In the copy, add a step to the "registration form" sub-flow. Choose "SignupBouncer signup check" and set it to
   Required.
6. Click the gear icon next to the step. Give its settings an alias and paste your API key. Leave "Refuse signups marked
   challenge" off, "Send the visitor's IP address" on and "App ID (older keys only)" empty, then save.
7. From the flow's Action menu, choose "Bind flow" and pick "Registration flow".

### Behind a proxy or load balancer

Keycloak sees the address of whatever connects to it. Behind a proxy, that's the proxy, so every signup reaches us with
the proxy's IP address. Our IP checks and burst checks then treat all your signups as coming from the same address.

To pass on the visitor's address, make your proxy overwrite the `X-Forwarded-For` header with it. A proxy that adds to
the header instead keeps whatever the visitor sent. Then start Keycloak with `--proxy-headers xforwarded` and
`--proxy-trusted-addresses` set to your proxy's addresses. If your proxy sets the standard `Forwarded` header, use
`--proxy-headers forwarded` instead. Keycloak's [reverse proxy guide](https://www.keycloak.org/server/reverseproxy) has
the details.

If someone can reach Keycloak without going through the proxy, or the proxy adds to the header, the person signing up
can choose the IP address we check. When you can't rule that out, turn off "Send the visitor's IP address" in the step's
settings. We then check the email address only.

### Check that it works

If your realm's login page has no Register link, turn on User registration under Realm settings, Login.

Register with a test address. Keycloak creates the account, and the signup appears on your dashboard's Checks tab within
seconds.

Your SignupBouncer app starts in shadow mode, so we log each signup and refuse nothing. When the Checks tab looks right,
switch the app to enforce mode on the Rules tab.

If no signup appears, look for a line starting with `SignupBouncer:` in Keycloak's log. A wrong or revoked API key lets
every signup through unchecked, and the line says so.

## Settings

| Setting                         | Default | What it does                                                                                                     |
| ------------------------------- | ------- | ---------------------------------------------------------------------------------------------------------------- |
| API key                         |         | Your app's `sb_live_...` key. Without it, every signup goes through unchecked and Keycloak logs a warning.       |
| Refuse signups marked challenge | Off     | Off: a signup marked challenge goes through. On: it's refused like a block, unless burst points helped cause it. |
| Send the visitor's IP address   | On      | Off: we check the email address only. See "Behind a proxy or load balancer" before you leave it on.              |
| App ID (older keys only)        | empty   | Leave this empty unless your key shows "all apps (older key)" on the dashboard. Then paste the `app_...` ID.     |

With a wrong App ID, every signup goes through unchecked and Keycloak logs a warning.

A challenge is a signup we find suspicious but not clear enough to refuse, such as the third spelling of the same inbox
within 7 days. With "Refuse signups marked challenge" on, we still let through a challenge that burst points helped
cause, as SignupBouncer's Supabase and Ory hooks do. Bursts are a sign of abuse, and also of a class signing up
together.

## What the person signing up sees

When we refuse a signup, the registration form comes back with a message under the email field. The message is the one
you set on the Rules tab of your SignupBouncer dashboard. While you keep our default, we word it for the reason, such as
"Did you mean ann@gmail.com?" for a domain that looks like a typo of a big mail provider. If your form has no email
field, we check the IP address alone, and Keycloak shows a refusal above the form.

To use your own words in Keycloak, and translate them, open Realm settings, Localization, Realm overrides and add the
key `signupbouncerRefused` for each language. Your text replaces our message for every reason. Put `{0}` in it where you
want our message to appear.

## If SignupBouncer is slow or down

The step waits up to 1.5 seconds for SignupBouncer's answer. When the call fails or times out, or SignupBouncer's answer
is unreadable, the signup goes through unchecked. Keycloak logs a warning with the cause. A wrong or revoked API key
lets the signup through the same way.

Only a complete answer from SignupBouncer can refuse a signup. The exception is an email address over 320 characters.
The step refuses it without a call, as every other SignupBouncer integration does, because no real address is that long.

Keycloak runs every step of the registration form each time someone sends it, even when another step finds a mistake. So
a form sent back for a password typo and sent again uses two checks from your monthly allowance. On the Free plan, after
1,000 checks in a month, we let signups through unchecked until the month ends.

## What gets sent

Each time someone sends the registration form, the step calls `POST https://signupbouncer.com/v1/check`. The call
carries the email address the account will get, the visitor's IP address and their browser's User-Agent. You can turn
off the IP address in the step's settings. The call sends your API key and the User-Agent
`signupbouncer-keycloak/<version>`.

The SignupBouncer step calls SignupBouncer through Keycloak's own HTTP client, the one Keycloak uses for its other
outgoing requests. If Keycloak reaches the internet through a proxy, the call to SignupBouncer goes through that proxy
too. You name the proxy in the `HTTPS_PROXY` environment variable or in Keycloak's `proxy-mappings` option. Keycloak's
[outgoing HTTP guide](https://www.keycloak.org/server/outgoinghttp) has the details.

Keycloak's log has a line for each refused, challenged or unchecked signup, with the outcome and SignupBouncer's check
id, never the key or the address. Allowed signups appear at debug level. If you turn on Save events under Realm
settings, Events, User events settings, each registration event carries `signupbouncer_outcome` and
`signupbouncer_check_id`.

When Keycloak starts, it logs a warning that the extension "is implementing the internal SPI form-action". Keycloak's
own registration steps, reCAPTCHA among them, use the same interface.

## Build and test

You need Java 17 or later and Maven 3.8 or later, or a container engine:

```sh
mvn verify                   # unit tests, then target/keycloak-signupbouncer-0.1.0.jar
bash scripts/build.sh        # the same in a maven:3.9-eclipse-temurin-21 container (podman or docker)
bash test/e2e.sh             # a real Keycloak 26.8.1 in a container, against test/stub.ts (needs deno, curl, jq, python3)
```

The end-to-end run sends the real registration form in these cases:

- an address SignupBouncer allows, and one it blocks;
- a blocked address sent as `user.attributes.email`, another field name Keycloak accepts;
- a challenge, with "Refuse signups marked challenge" off and then on, and a challenge from burst points;
- an answer that takes 3 seconds, a server error and an answer that isn't JSON;
- a wrong API key;
- realm overrides of the message, with and without `{0}`;
- a realm whose form has no email field, from a refused IP address;
- the API stopped;
- Keycloak behind an outgoing proxy, set with `proxy-mappings` (with a login) and then with `HTTPS_PROXY`.

## License

MIT. See [LICENSE](LICENSE).
