# Changelog

## 0.2.1 (2026-11-17)

- When 64 checks are already running, the next signup now waits for one to finish, inside the 1.5 seconds the step waits
  for SignupBouncer's answer. Before, it went through unchecked right away. If none finishes in time, the signup still
  goes through unchecked. Keycloak's log and the registration event now give that signup the outcome `busy`, where they
  gave `network_error` before.

## 0.2.0 (2026-11-07)

- "Refuse signups marked challenge" now lets through a challenge that the repeat-home check helped cause, as it already
  did for the burst checks. On the Pro plan, the repeat-home check (reason code `repeat_ip`) flags the third different
  inbox used to sign up from the same home IP address within 7 days.
- The setting's help text says so, and gives a current example of a challenge: an address on a free subdomain service.
- If SignupBouncer refuses your API key, the warning in Keycloak's log now also covers a key you rotated over 24 hours
  ago or whose app you removed. The warning then gives the steps to get a working key.
- Tested with Keycloak 26.8.1.

## 0.1.0

- First release: the "SignupBouncer signup check" step for Keycloak registration forms, tested with Keycloak 26.8.1.
