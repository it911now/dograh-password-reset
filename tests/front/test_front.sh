#!/usr/bin/env bash
# Tests the nginx front (front/nginx.conf.template) against a stub UI and the real add-on.
#   ./test_front.sh
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SECRETS_DIR="$(mktemp -d)"; export SECRETS_DIR
chmod 755 "$SECRETS_DIR"
printf 'postgresql://postgres:test-only-password@pg:5432/dograh_test\n' >"$SECRETS_DIR/db_url"
printf 'test-only-webhook-secret\n' >"$SECRETS_DIR/webhook_secret"
chmod 644 "$SECRETS_DIR"/*
COMPOSE=(docker compose -p dpr-front-test -f "$HERE/compose.front.yaml")
trap '"${COMPOSE[@]}" down -v >/dev/null 2>&1; rm -rf "$SECRETS_DIR"' EXIT

fails=0
check() { # name, ok(0/1), detail
  if [ "$2" = 0 ]; then echo "PASS $1"; else echo "FAIL $1 -- $3"; fails=$((fails+1)); fi
}

# Cold start: the add-on service has never been started; the front must still come up and serve the UI.
"${COMPOSE[@]}" up -d --no-deps ui front >/dev/null 2>&1 || { echo "FAIL cold-start compose up"; exit 1; }
CPORT="$("${COMPOSE[@]}" port front 80 | sed 's/.*://')"
for _ in $(seq 1 30); do
  [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$CPORT/auth/login")" = 200 ] && break
  sleep 1
done
code="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$CPORT/auth/login")"
[ "$code" = 200 ]; check "cold start (add-on never started): HTML 200" $? "got $code"
[ "$("${COMPOSE[@]}" ps --status running --services | grep -c '^front$')" = 1 ]; check "cold start: nginx is running" $? "front not running"

"${COMPOSE[@]}" up -d --build >/dev/null 2>&1 || { echo "FAIL compose up"; "${COMPOSE[@]}" logs 2>&1 | tail -30; exit 1; }
PORT="$("${COMPOSE[@]}" port front 80 | sed 's/.*://')"
FRONT="http://127.0.0.1:$PORT"

# Wait for the add-on to answer through the front.
for _ in $(seq 1 60); do
  [ "$(curl -s -o /dev/null -w '%{http_code}' "$FRONT/password-reset/healthz")" = 200 ] && break
  sleep 1
done

TAG='<script src="/password-reset/inject.js" defer></script>'

html="$(curl -s "$FRONT/auth/login")"
n="$(grep -o -F "$TAG" <<<"$html" | wc -l)"
[ "$n" = 1 ]; check "HTML contains the script tag exactly once" $? "found $n"
grep -q -F "$TAG</body>" <<<"$html"; check "tag sits right before </body>" $? "$html"

curl -s "$FRONT/_next/static/app.js" >"$SECRETS_DIR/asset.out"
cmp -s "$SECRETS_DIR/asset.out" "$HERE/stub-ui/app.js"; check "JS asset is byte-identical" $? "differs"

code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 \
  -H 'Connection: Upgrade' -H 'Upgrade: websocket' -H 'Sec-WebSocket-Version: 13' \
  -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' "$FRONT/ws")"
[ "$code" = 101 ]; check "websocket upgrade returns 101" $? "got $code"

curl -s "$FRONT/_next/static/note.txt" >"$SECRETS_DIR/note.out"
printf 'not a page: </body> stays as is\n' | cmp -s - "$SECRETS_DIR/note.out"; check "non-HTML body with </body> is byte-identical" $? "rewritten: $(cat "$SECRETS_DIR/note.out")"

p="$(curl -s "$FRONT/echo-proto")"
[ "$p" = http ]; check "X-Forwarded-Proto is http when the client sends none" $? "got $p"
p="$(curl -s -H 'X-Forwarded-Proto: https' "$FRONT/echo-proto")"
[ "$p" = https ]; check "X-Forwarded-Proto https from the tunnel is kept" $? "got $p"

code="$(curl -s -o /dev/null -w '%{http_code}' "$FRONT/big-headers")"
[ "$code" = 200 ]; check "12k response headers do not cause a 502" $? "got $code"

body="$(curl -s "$FRONT/password-reset/healthz")"
code="$(curl -s -o /dev/null -w '%{http_code}' "$FRONT/password-reset/healthz")"
[ "$code" = 200 ]; check "BASE_PATH/healthz reaches the add-on" $? "got $code: $body"

code="$(curl -s -o /dev/null -w '%{http_code}' "$FRONT/password-reset/inject.js")"
[ "$code" = 200 ]; check "BASE_PATH/inject.js is served" $? "got $code"

code="$(curl -s -o /dev/null -w '%{http_code} %{redirect_url}' "$FRONT/password-reset")"
[ "${code%% *}" = 200 ]; check "BASE_PATH without slash serves the request page" $? "got $code"

code="$(curl -s -o /dev/null -w '%{http_code}' "$FRONT/__front_health")"
[ "$code" = 204 ]; check "/__front_health is answered by nginx (204)" $? "got $code"

"${COMPOSE[@]}" stop password-reset >/dev/null 2>&1
code="$(curl -s -o /dev/null -w '%{http_code}' "$FRONT/__front_health")"
[ "$code" = 204 ]; check "/__front_health still 204 with the add-on stopped" $? "got $code"
code="$(curl -s -o /dev/null -w '%{http_code}' "$FRONT/auth/login")"
[ "$code" = 200 ]; check "HTML still 200 with the add-on stopped" $? "got $code"
code="$(curl -s -o /dev/null -w '%{http_code}' "$FRONT/password-reset/healthz")"
[[ "$code" =~ ^50[234]$ ]]; check "add-on paths fail cleanly (50x) when it is down" $? "got $code"

[ "$fails" = 0 ] && echo "ALL PASSED" || { echo "$fails FAILED"; exit 1; }
