#!/usr/bin/env bash
# End-to-end run of the SignupBouncer form action in a real Keycloak, in podman (or docker), against test/stub.ts.
#
#   bash scripts/build.sh            # builds target/keycloak-signupbouncer-<version>.jar
#   bash test/e2e.sh                 # needs deno, curl, jq and python3
#
# Keycloak runs start-dev with host networking on 127.0.0.1:8095 (management 9095), the jar in /opt/keycloak/providers,
# proxy-headers=xforwarded (so the X-Forwarded-For the run sends becomes the visitor's IP), and the server option
# base-url pointing the extension at the stub on 127.0.0.1:8097. The run creates a realm, copies its registration flow,
# adds the "SignupBouncer signup check" step, binds the copy, then submits the real registration form with curl:
#
#   1. allow: the account is created, and the stub saw the email, the forwarded IP, our User-Agent and the key;
#   2. block: the form comes back with the stub's message on the email field, and no account exists;
#   3. challenge, with the default settings: the account is created;
#   4. challenge, with "Refuse signups marked challenge" on: refused like a block;
#   5. a stub that takes 3 seconds: the account is created after about 1.5 seconds;
#   6. a 500 from the stub: the account is created;
#   7. a 200 that is not JSON: the account is created;
#   8. a wrong API key (401): the account is created, though the address would be blocked;
#   9. a realm override of the message key: a block shows the realm's own words;
#  10. the stub stopped: the account is created;
#  11. a blocked address sent as user.attributes.email (another name Keycloak accepts): refused;
#  12. a challenge that burst points helped cause, with challenges refused: the account is created, as in the hooks;
#  13. a realm without email on its form, a refused IP: the message shows above the form;
#  14. Keycloak restarted with proxy-mappings naming an outgoing proxy that needs a login (test/proxy.py on 8098): the
#      check goes through that proxy with its credentials, and a block is refused;
#  15. Keycloak restarted with no proxy-mappings and HTTPS_PROXY set instead: the check goes through that proxy.
# 9b checks a realm override that keeps {0}, SignupBouncer's message. SPI_OPTION names the base-url server option
# (Keycloak 25 spells it --spi-form-action-signupbouncer-base-url), and PROXY_OPTION the proxy-mappings one (Keycloak 25:
# --spi-connections-http-client-default-proxy-mappings). PROXY_TRUSTED= drops --proxy-trusted-addresses, which Keycloak
# 25 doesn't have.
#
# Ports, image and jar can be changed with KC_PORT, KC_MGMT_PORT, STUB_PORT, PROXY_PORT, KC_IMAGE and JAR. The container
# is removed at the end; the stub and the proxy are stopped. Prints "RESULT: N passed, M failed" and exits non-zero on
# any failure.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
pkg="$(cd "$here/.." && pwd)"
KC_IMAGE="${KC_IMAGE:-quay.io/keycloak/keycloak:26.8.1}"
KC_PORT="${KC_PORT:-8095}"
KC_MGMT_PORT="${KC_MGMT_PORT:-9095}"
STUB_PORT="${STUB_PORT:-8097}"
PROXY_PORT="${PROXY_PORT:-8098}"
NAME=sb-keycloak-e2e
KC="http://127.0.0.1:$KC_PORT"
STUB="http://127.0.0.1:$STUB_PORT"
REALM=sbtest
FLOW="sb registration"
CLIENT=sb-e2e
REDIRECT="$KC/e2e-done"
engine="$(command -v podman || command -v docker)"
jar="${JAR:-$(ls "$pkg"/target/keycloak-signupbouncer-*.jar 2>/dev/null | head -1)}"
[ -n "$jar" ] && [ -f "$jar" ] || { echo "No jar: run bash scripts/build.sh first" >&2; exit 2; }
work="$(mktemp -d)"
pass=0
fail=0
stub_pid=""
proxy_pid=""

ok() { echo "PASS: $1"; pass=$((pass + 1)); }
bad() { echo "FAIL: $1"; fail=$((fail + 1)); }

cleanup() {
  "$engine" rm -f "$NAME" >/dev/null 2>&1 || true
  [ -n "$stub_pid" ] && kill "$stub_pid" 2>/dev/null || true
  [ -n "$proxy_pid" ] && kill "$proxy_pid" 2>/dev/null || true
  rm -rf "$work"
}
[ -n "${KEEP:-}" ] && trap '[ -n "$stub_pid" ] && kill "$stub_pid" 2>/dev/null; [ -n "$proxy_pid" ] && kill "$proxy_pid" 2>/dev/null; echo kept "$work"' EXIT || trap cleanup EXIT

start_stub() {
  deno run --allow-net="127.0.0.1:$STUB_PORT" "$here/stub.ts" "$STUB_PORT" >"$work/stub.log" 2>&1 &
  stub_pid=$!
  for _ in $(seq 1 50); do
    curl -fsS "$STUB/requests" >/dev/null 2>&1 && return 0
    sleep 0.1
  done
  cat "$work/stub.log"
  echo "stub did not start" >&2
  exit 1
}

# Starts the outgoing proxy (test/proxy.py), logging to $1, with the login $2 if given.
start_proxy() {
  [ -n "$proxy_pid" ] && kill "$proxy_pid" 2>/dev/null && wait "$proxy_pid" 2>/dev/null || true
  : >"$1"
  python3 -I "$here/proxy.py" "$PROXY_PORT" "$1" ${2:+"$2"} >"$work/proxy.out" 2>&1 &
  proxy_pid=$!
  for _ in $(seq 1 50); do
    curl -sS -o /dev/null "http://127.0.0.1:$PROXY_PORT/" 2>/dev/null && return 0
    sleep 0.1
  done
  cat "$work/proxy.out"
  echo "proxy did not start" >&2
  exit 1
}

# ---- Keycloak -------------------------------------------------------------------------------------------------------

# Starts a fresh Keycloak container. Arguments: extra `podman run` options (such as -e NAME=value), then `--`, then
# extra server options.
start_keycloak() {
  local run_opts=() kc_opts=()
  while [ $# -gt 0 ] && [ "$1" != "--" ]; do run_opts+=("$1"); shift; done
  [ $# -gt 0 ] && shift
  kc_opts=("$@")
  "$engine" rm -f "$NAME" >/dev/null 2>&1 || true
  "$engine" run -d --name "$NAME" --network host \
    -v "$jar:/opt/keycloak/providers/keycloak-signupbouncer.jar:ro,Z" \
    -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=admin \
    ${run_opts[@]+"${run_opts[@]}"} \
    "$KC_IMAGE" start-dev --http-host=127.0.0.1 --http-port="$KC_PORT" --http-management-port="$KC_MGMT_PORT" \
    --proxy-headers=xforwarded ${PROXY_TRUSTED---proxy-trusted-addresses=127.0.0.1} \
    "${SPI_OPTION:---spi-form-action--signupbouncer--base-url}=$STUB" ${kc_opts[@]+"${kc_opts[@]}"} >/dev/null
  for i in $(seq 1 180); do
    if curl -fsS "$KC/realms/master" >/dev/null 2>&1; then break; fi
    if [ "$i" = 180 ]; then
      "$engine" logs "$NAME" 2>&1 | tail -40
      echo "Keycloak did not start" >&2
      exit 1
    fi
    sleep 1
  done
  "$engine" logs "$NAME" 2>&1 | grep -E 'SignupBouncer|signupbouncer' | head -5 || true
}

echo "Keycloak: $KC_IMAGE, jar: $(basename "$jar")"
start_stub
start_keycloak

token() {
  curl -fsS "$KC/realms/master/protocol/openid-connect/token" -d grant_type=password -d client_id=admin-cli \
    -d username=admin -d password=admin | jq -r .access_token
}
admin() { # method path [json]
  local m="$1" p="$2"
  shift 2
  curl -fsS -X "$m" "$KC/admin/realms$p" -H "Authorization: Bearer $(token)" -H 'Content-Type: application/json' "$@"
}
urlenc() { jq -rn --arg v "$1" '$v|@uri'; }

# ---- Realm, client and flow -----------------------------------------------------------------------------------------

setup_realm() {
admin POST "" --data "{\"realm\":\"$REALM\",\"enabled\":true,\"registrationAllowed\":true,\"registrationEmailAsUsername\":true,\"sslRequired\":\"none\"}" >/dev/null
admin POST "/$REALM/clients" --data "{\"clientId\":\"$CLIENT\",\"publicClient\":true,\"standardFlowEnabled\":true,\"redirectUris\":[\"$REDIRECT\"]}" >/dev/null
admin POST "/$REALM/authentication/flows/registration/copy" --data "{\"newName\":\"$FLOW\"}" >/dev/null
flow_enc="$(urlenc "$FLOW")"
form_flow="$(admin GET "/$REALM/authentication/flows/$flow_enc/executions" | jq -r '[.[] | select(.authenticationFlow == true)][0].displayName')"
admin POST "/$REALM/authentication/flows/$(urlenc "$form_flow")/executions/execution" --data '{"provider":"signupbouncer"}' >/dev/null
execution="$(admin GET "/$REALM/authentication/flows/$flow_enc/executions" | jq -c '.[] | select(.providerId == "signupbouncer")')"
execution_id="$(jq -r .id <<<"$execution")"
admin PUT "/$REALM/authentication/flows/$flow_enc/executions" --data "$(jq -c '.requirement = "REQUIRED"' <<<"$execution")" >/dev/null
admin POST "/$REALM/authentication/executions/$execution_id/config" \
  --data '{"alias":"signupbouncer","config":{"apiKey":"sb_live_e2e","refuseChallenge":"false","sendIp":"true"}}' >/dev/null
config_id="$(admin GET "/$REALM/authentication/flows/$flow_enc/executions" | jq -r '.[] | select(.providerId == "signupbouncer") | .authenticationConfig')"
admin PUT "/$REALM" --data "{\"registrationFlow\":\"$FLOW\"}" >/dev/null
echo "Flow \"$FLOW\": $(admin GET "/$REALM/authentication/flows/$flow_enc/executions" | jq -r '[.[] | "\(.displayName) (\(.requirement))"] | join(", ")')"
}
setup_realm

set_config() { # json object of settings
  admin PUT "/$REALM/authentication/config/$config_id" --data "{\"id\":\"$config_id\",\"alias\":\"signupbouncer\",\"config\":$1}" >/dev/null
}

# ---- One registration -----------------------------------------------------------------------------------------------

# Sends the registration form with the given fields (curl --data-urlencode arguments), from X-Forwarded-For $XFF
# (default 203.0.113.7). Prints "<HTTP status> <seconds> <message on the email field, or ->" and keeps the page.
send_form() {
  local jar="$work/cookies" page="$work/page.html" action
  rm -f "$jar"
  curl -fsS -c "$jar" -b "$jar" -o "$page" \
    "$KC/realms/$REALM/protocol/openid-connect/registrations?client_id=$CLIENT&response_type=code&scope=openid&redirect_uri=$(urlenc "$REDIRECT")"
  action="$(python3 -I "$here/form.py" action "$page")"
  curl -sS -c "$jar" -b "$jar" -o "$page" -w '%{http_code} %{time_total} ' -X POST "$action" \
    -H "X-Forwarded-For: ${XFF:-203.0.113.7}" -H 'User-Agent: sb-keycloak-e2e-browser' \
    --data-urlencode "firstName=Ann" --data-urlencode "lastName=Example" \
    --data-urlencode "password=correct horse battery staple 42" \
    --data-urlencode "password-confirm=correct horse battery staple 42" "$@"
  python3 -I "$here/form.py" email-error "$page"
}

# Sends the registration form for the address $1.
register() { send_form --data-urlencode "email=$1"; }

user_exists() { # email
  [ "$(admin GET "/$REALM/users?email=$(urlenc "$1")&exact=true" | jq length)" -gt 0 ]
}

n=$RANDOM$RANDOM
STUB_MESSAGE="Stub refusal: we don't take this address."

expect_created() { # case-label email
  local out
  out="$(register "$2")"
  echo "  $2 -> $out"
  if [[ "$out" == 302* ]] && user_exists "$2"; then ok "$1"; else bad "$1"; fi
}
expect_refused() { # case-label email message
  local out
  out="$(register "$2")"
  echo "  $2 -> $out"
  if [[ "$out" == 200* ]] && [[ "$out" == *"$3"* ]] && ! user_exists "$2"; then ok "$1"; else bad "$1"; fi
}

expect_created "1. allow: account created" "allow.$n@example.com"
last="$(curl -fsS "$STUB/requests" | jq -c '.[-1]')"
echo "  stub saw: $last"
if jq -e --arg e "allow.$n@example.com" '.keyOk and .body.email == $e and .body.ip == "203.0.113.7"
    and .body.user_agent == "sb-keycloak-e2e-browser" and (.userAgent | startswith("signupbouncer-keycloak/"))
    and (.body | has("attempt_id") | not)' <<<"$last" >/dev/null; then
  ok "1b. the check carried the email, the forwarded IP, the browser's User-Agent, the key and our User-Agent"
else
  bad "1b. the check carried the email, the forwarded IP, the browser's User-Agent, the key and our User-Agent"
fi

expect_refused "2. block: refused with SignupBouncer's message on the email field" "block.$n@example.com" "$STUB_MESSAGE"
expect_created "3. challenge, default settings: account created" "challenge.$n@example.com"

set_config '{"apiKey":"sb_live_e2e","refuseChallenge":"true","sendIp":"true"}'
expect_refused "4. challenge, refuse challenges on: refused" "challenge2.$n@example.com" "$STUB_MESSAGE"
set_config '{"apiKey":"sb_live_e2e","refuseChallenge":"false","sendIp":"true"}'

out="$(register "slow.$n@example.com")"
echo "  slow.$n@example.com -> $out"
secs="$(cut -d' ' -f2 <<<"$out")"
if [[ "$out" == 302* ]] && user_exists "slow.$n@example.com" && python3 -I -c "import sys; t=float(sys.argv[1]); sys.exit(0 if 1.4 <= t < 3.0 else 1)" "$secs"; then
  ok "5. slow answer: account created after ${secs}s (gave up at 1.5 s)"
else
  bad "5. slow answer: account created within the deadline (took ${secs}s)"
fi

expect_created "6. HTTP 500: account created" "error500.$n@example.com"
expect_created "7. HTTP 200 that is not JSON: account created" "junk.$n@example.com"

set_config '{"apiKey":"sb_live_wrong","refuseChallenge":"true","sendIp":"true"}'
expect_created "8. wrong API key (401), address the stub would block: account created" "block.wrongkey.$n@example.com"
set_config '{"apiKey":"sb_live_e2e","refuseChallenge":"false","sendIp":"true"}'

curl -fsS -X PUT "$KC/admin/realms/$REALM/localization/en/signupbouncerRefused" -H "Authorization: Bearer $(token)" \
  -H 'Content-Type: text/plain' --data 'Please use a work address to sign up.' >/dev/null
expect_refused "9. realm override of signupbouncerRefused: refused with the realm's words" "block.override.$n@example.com" \
  "Please use a work address to sign up."
curl -fsS -X PUT "$KC/admin/realms/$REALM/localization/en/signupbouncerRefused" -H "Authorization: Bearer $(token)" \
  -H 'Content-Type: text/plain' --data 'Sign-up refused. {0}' >/dev/null
expect_refused "9b. realm override that keeps {0}: the realm's words and SignupBouncer's message" \
  "block.override2.$n@example.com" "Sign-up refused. $STUB_MESSAGE"
curl -fsS -X DELETE "$KC/admin/realms/$REALM/localization/en/signupbouncerRefused" -H "Authorization: Bearer $(token)" >/dev/null

# Keycloak also takes the address as user.attributes.email. The step must check the address the account gets.
out="$(send_form --data-urlencode "user.attributes.email=block.attr.$n@example.com")"
echo "  user.attributes.email=block.attr.$n@example.com -> $out"
if [[ "$out" == 200* ]] && ! user_exists "block.attr.$n@example.com"; then
  ok "11. blocked address sent as user.attributes.email: refused, no account"
else
  bad "11. blocked address sent as user.attributes.email: refused, no account"
fi

set_config '{"apiKey":"sb_live_e2e","refuseChallenge":"true","sendIp":"true"}'
expect_created "12. challenge from burst points, refuse challenges on: account created (as in the hooks)" \
  "burstchallenge.$n@example.com"
set_config '{"apiKey":"sb_live_e2e","refuseChallenge":"false","sendIp":"true"}'

# A realm whose registration form has no email: the step checks the IP alone, and a refusal shows above the form.
admin PUT "/$REALM" --data '{"registrationEmailAsUsername":false}' >/dev/null
admin GET "/$REALM/users/profile" >"$work/profile-orig.json"
jq '.attributes |= map(if .name == "email" then del(.required) | .permissions = {"view": ["admin"], "edit": ["admin"]} else . end)' \
  "$work/profile-orig.json" >"$work/profile.json"
admin PUT "/$REALM/users/profile" --data @"$work/profile.json" >/dev/null
user="ipblock$n"
out="$(XFF=203.0.113.66 send_form --data-urlencode "username=$user")"
echo "  username=$user from 203.0.113.66 -> $out"
last="$(curl -fsS "$STUB/requests" | jq -c '.[-1].body')"
echo "  stub saw: $last"
if [[ "$out" == 200* ]] && python3 -I "$here/form.py" has-text "$work/page.html" "$STUB_MESSAGE" &&
  [ "$(admin GET "/$REALM/users?username=$user&exact=true" | jq length)" = 0 ] &&
  jq -e '(has("email") | not) and (.attempt_id | startswith("kc:"))' <<<"$last" >/dev/null; then
  ok "13. no email on the form, IP refused: message above the form, no account, attempt_id sent"
else
  bad "13. no email on the form, IP refused: message above the form, no account, attempt_id sent"
fi
admin PUT "/$REALM/users/profile" --data @"$work/profile-orig.json" >/dev/null
admin PUT "/$REALM" --data '{"registrationEmailAsUsername":true}' >/dev/null

kill "$stub_pid" 2>/dev/null || true
wait "$stub_pid" 2>/dev/null || true
stub_pid=""
proxy_pid=""
expect_created "10. stub stopped (connection refused), address it would block: account created" "block.down.$n@example.com"

# ---- Keycloak's outgoing proxy --------------------------------------------------------------------------------------

# A network where Keycloak reaches the internet only through a proxy. The step must send its check the way Keycloak sends
# its own outgoing calls: through the proxy that proxy-mappings names, with its login, or else through HTTPS_PROXY.
start_stub
proxied() { # proxy log [auth]: the last request the proxy saw was the check, with the login when $2 is "auth"
  local last
  last="$(tail -1 "$1")"
  echo "  proxy saw: ${last:-nothing}"
  jq -e --arg u "$STUB/v1/check" --arg auth "${2:-}" '.method == "POST" and .url == $u
      and (.userAgent | startswith("signupbouncer-keycloak/")) and ($auth == "" or .auth)' <<<"${last:-null}" >/dev/null
}

start_proxy "$work/proxy-mappings.log" "kc:e2e-secret"
start_keycloak -- "${PROXY_OPTION:---spi-connections-http-client--default--proxy-mappings}=.*;http://kc:e2e-secret@127.0.0.1:$PROXY_PORT"
setup_realm
out="$(register "block.proxied.$n@example.com")"
echo "  block.proxied.$n@example.com -> $out"
if [[ "$out" == 200* ]] && [[ "$out" == *"$STUB_MESSAGE"* ]] && ! user_exists "block.proxied.$n@example.com" &&
  proxied "$work/proxy-mappings.log" auth; then
  ok "14. proxy-mappings: the check went through Keycloak's outgoing proxy with its login, and the block was refused"
else
  bad "14. proxy-mappings: the check went through Keycloak's outgoing proxy with its login, and the block was refused"
fi

start_proxy "$work/proxy-env.log"
start_keycloak -e "HTTPS_PROXY=http://127.0.0.1:$PROXY_PORT" -e "NO_PROXY=keycloak.invalid"
setup_realm
out="$(register "allow.envproxy.$n@example.com")"
echo "  allow.envproxy.$n@example.com -> $out"
if [[ "$out" == 302* ]] && user_exists "allow.envproxy.$n@example.com" && proxied "$work/proxy-env.log"; then
  ok "15. HTTPS_PROXY, no proxy-mappings: the check went through that proxy, and the account was created"
else
  bad "15. HTTPS_PROXY, no proxy-mappings: the check went through that proxy, and the account was created"
fi

echo "Keycloak log lines from the extension:"
"$engine" logs "$NAME" 2>&1 | grep -E 'SignupBouncer' | sed -E 's/^.*(SignupBouncer)/  \1/' | tail -12 || true
echo "RESULT: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
