#!/usr/bin/env bash
#
# Shared helpers for the stage demo (setup.sh + run-demo.sh).
# Source me; do not execute me.
#
# shellcheck disable=SC2034

# Colors
G='\033[0;32m'; R='\033[0;31m'; Y='\033[1;33m'; B='\033[1;36m'
C='\033[1;36m'; D='\033[0;90m'; NC='\033[0m'; BOLD='\033[1m'

# Resolve the demo dir and the repo root from the file that sourced us.
# Callers must set DEMO_DIR before sourcing, OR we infer from BASH_SOURCE.
if [ -z "${DEMO_DIR:-}" ]; then
    DEMO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fi
REPO_ROOT="$(cd "$DEMO_DIR/../.." && pwd)"
ENV_FILE="${ENV_FILE:-$DEMO_DIR/.demo-env}"
RECORDINGS_DIR="${RECORDINGS_DIR:-$DEMO_DIR/recordings}"
BIN="${BIN:-$REPO_ROOT/target/release/ebpf-mon}"

# Fixed container names / ports (must match setup.sh)
WORKLOAD_NAME="${WORKLOAD_NAME:-ebpf-mon-workload}"
VULNAPP_NAME="${VULNAPP_NAME:-vulnapp}"
SECRETSVC_NAME="${SECRETSVC_NAME:-secretsvc}"
VULNAPP_PORT="${VULNAPP_PORT:-8080}"
SECRETSVC_PORT="${SECRETSVC_PORT:-8081}"

# Background enforce bookkeeping
ENFORCE_PID=""
ENFORCE_LOG=""
ENFORCE_NAME=""

hr() { echo -e "${D}------------------------------------------------------------${NC}"; }

# serving <target> <path> [note]
# Colorful app-health line for the [C]/audit legit beats, styled like the
# SERVING/FAILED lines the attack scripts print so the "app still works" proof
# reads with the same visibility as CONTAINED/EXECUTED. Hits the app's REAL HTTP
# endpoint so the app process performs its own profiled in-process open (e.g.
# GET /health -> the app reads /app/config.txt itself) — the faithful health
# test, not a docker-exec of un-profiled tooling.
serving() {
    local target="$1" path="$2" note="${3:-}" resp code body
    resp="$(curl -s -m 5 -w $'\n%{http_code}' "http://$target$path" 2>/dev/null || true)"
    code="${resp##*$'\n'}"
    body="$(printf '%s' "${resp%$'\n'*}" | head -c 56 | tr -d '\n')"
    if [ "$code" = "200" ]; then
        echo -e "  ${G}SERVING  ${NC} GET $path   ${D}(HTTP $code${note:+ — $note})${NC}"
        [ -n "$body" ] && echo -e "${D}    -> ${body}${NC}"
    else
        echo -e "  ${R}FAILED   ${NC} GET $path   ${Y}(HTTP ${code:-timeout} — false positive?)${NC}"
    fi
}

pause() {
    local msg="${1:-Press Enter to continue...}"
    echo
    echo -e "${Y}${msg}${NC}"
    # Read from the real tty so this works even when stdout is piped / recorded.
    if [ -t 0 ]; then
        read -r -p "" || true
    elif [ -r /dev/tty ]; then
        read -r -p "" </dev/tty || true
    else
        sleep 2
    fi
}

chapter() {
    local num="$1" title="$2" blurb="${3:-}"
    echo
    hr
    echo -e "${C}${BOLD}CHAPTER $num — $title${NC}"
    if [ -n "$blurb" ]; then
        echo -e "${D}$blurb${NC}"
    fi
    hr
}

load_env() {
    if [ ! -f "$ENV_FILE" ]; then
        echo -e "${R}error:${NC} $ENV_FILE missing. Run docs/demo/setup.sh first." >&2
        return 1
    fi
    # shellcheck disable=SC1090
    set -a; source "$ENV_FILE"; set +a
    return 0
}

ensure_container() {
    local name="$1"
    if ! docker container inspect "$name" >/dev/null 2>&1; then
        echo -e "${R}error:${NC} container '$name' not found. Run docs/demo/setup.sh." >&2
        return 1
    fi
    local status
    status="$(docker container inspect -f '{{.State.Status}}' "$name" 2>/dev/null || echo missing)"
    if [ "$status" != "running" ]; then
        echo -e "${Y}warning:${NC} '$name' is $status — attempting start..."
        docker start "$name" >/dev/null || {
            echo -e "${R}error:${NC} could not start '$name'"; return 1; }
        sleep 1
    fi
    return 0
}

# start_enforce <container-name> <events.json> [--audit-only]
# Spawns ebpf-mon in the background; logs go to a temp file we can later dump.
start_enforce() {
    local name="$1" events="$2"; shift 2
    local extra=("$@")
    stop_enforce >/dev/null 2>&1 || true

    [ -x "$BIN" ] || { echo -e "${R}error:${NC} binary not found: $BIN (run setup.sh)"; return 1; }
    [ -r "$events" ] || { echo -e "${R}error:${NC} profile not found: $events"; return 1; }
    ensure_container "$name" || return 1

    # Refresh sudo credentials in the FOREGROUND first, while we still own the
    # terminal. The enforcer below is backgrounded with stdout/stderr redirected
    # to a log, so if sudo's timestamp has expired — which is common by chapter
    # 7/8 after minutes of reading through the userspace-only chapters 2-6 that
    # never call sudo — the backgrounded `sudo` can't prompt: it blocks on
    # /dev/tty for a password, the binary never execs, the log stays EMPTY, and
    # start_enforce fails with "did not reach READY within timeout. Log: (empty)".
    # Prompting now (foreground) primes the timestamp so the background sudo runs
    # non-interactively.
    if ! sudo -n true 2>/dev/null; then
        echo -e "${Y}[enforce] sudo needs your password to load eBPF programs...${NC}"
    fi
    if ! sudo -v; then
        echo -e "${R}error:${NC} sudo authentication failed (required to load eBPF enforcement)"
        return 1
    fi

    ENFORCE_LOG="$(mktemp --suffix=-enforce.log)"
    ENFORCE_NAME="$name"
    # Exported so the attack scripts (cve-demo.sh / exfil-demo.sh), which run as
    # child processes, can tail the live enforcer log and print a per-attack
    # "kernel receipt" (the ENFORCEMENT DENY/AUDIT line) under each result.
    export ENFORCE_LOG
    # sudo env RUST_LOG=info — survives strict sudo policies that ignore -E.
    # Run from ebpf-mon/ so final-events.json (if any) lands in the usual place.
    (
        cd "$REPO_ROOT/ebpf-mon"
        sudo env RUST_LOG=info "$BIN" --name "$name" --enforce "$events" "${extra[@]}"
    ) >"$ENFORCE_LOG" 2>&1 &
    ENFORCE_PID=$!

    # Wait until the process is alive and has printed the READY sentinel
    # (or timed out after ~25s of attach work).
    local i=0
    while [ $i -lt 50 ]; do
        if ! kill -0 "$ENFORCE_PID" 2>/dev/null; then
            echo -e "${R}error:${NC} enforce process died. Log:"
            sed 's/^/  /' "$ENFORCE_LOG" | tail -40
            ENFORCE_PID=""; return 1
        fi
        # Wait for the DEFINITIVE readiness sentinel the binary prints only after
        # EVERY program has loaded AND attached. The earlier "Enforcement:" banner
        # prints mid-startup, so a later attach/verifier failure (e.g. a cgroup_skb
        # bpf_link_create ENOENT) would slip past as a false "ready" and every
        # attack would then show ALLOWED. Waiting for READY closes that window.
        if grep -qE '^READY:' "$ENFORCE_LOG" 2>/dev/null; then
            echo -e "${G}[enforce]${NC} $name pid=$ENFORCE_PID  log=$ENFORCE_LOG  ${extra[*]:-LIVE}"
            return 0
        fi
        # If the process died before READY, surface the failure loudly.
        if grep -qiE 'BPF_PROG_LOAD|verifier|not pointing to valid bpf_map|bpf_link_create|^Error:|Caused by:' "$ENFORCE_LOG" 2>/dev/null; then
            echo -e "${R}error:${NC} enforce process failed to come up (load/attach error). Log:"
            sed 's/^/  /' "$ENFORCE_LOG" | tail -40
            stop_enforce >/dev/null 2>&1 || true
            ENFORCE_PID=""; return 1
        fi
        sleep 0.5
        i=$((i+1))
    done
    # No READY within the window and no crash detected — treat as a failure
    # rather than proceeding into attacks with an unconfirmed enforcer.
    echo -e "${R}error:${NC} enforce did not reach READY within timeout. Log:"
    if [ -s "$ENFORCE_LOG" ]; then
        sed 's/^/  /' "$ENFORCE_LOG" | tail -40
    else
        # An empty log means the binary never printed anything — almost always
        # sudo blocking for a password it can't read (expired timestamp under a
        # backgrounded, redirected launch), or the kernel lacking BPF-LSM.
        echo -e "  ${D}(log is empty — the enforcer produced no output)${NC}"
        echo -e "  ${Y}likely causes:${NC}"
        echo -e "    ${D}1. sudo needed a password but couldn't prompt (backgrounded). Run${NC}"
        echo -e "       ${D}'sudo -v' in this terminal first, then re-run the chapter.${NC}"
        echo -e "    ${D}2. kernel lacks BPF-LSM. Check: cat /sys/kernel/security/lsm${NC}"
        echo -e "       ${D}(must include 'bpf'); enable via lsm=...,bpf on the kernel cmdline.${NC}"
    fi
    stop_enforce >/dev/null 2>&1 || true
    ENFORCE_PID=""; return 1
}

stop_enforce() {
    if [ -n "${ENFORCE_PID:-}" ] && kill -0 "$ENFORCE_PID" 2>/dev/null; then
        # INT so it flushes cleanly (same as Ctrl+C).
        sudo kill -INT "$ENFORCE_PID" 2>/dev/null || kill -INT "$ENFORCE_PID" 2>/dev/null || true
        # Wait up to 5s, then TERM.
        local i=0
        while [ $i -lt 10 ] && kill -0 "$ENFORCE_PID" 2>/dev/null; do
            sleep 0.5; i=$((i+1))
        done
        if kill -0 "$ENFORCE_PID" 2>/dev/null; then
            sudo kill -TERM "$ENFORCE_PID" 2>/dev/null || kill -TERM "$ENFORCE_PID" 2>/dev/null || true
        fi
        wait "$ENFORCE_PID" 2>/dev/null || true
        echo -e "${D}[enforce] stopped pid=$ENFORCE_PID ($ENFORCE_NAME)${NC}"
    fi
    ENFORCE_PID=""
    ENFORCE_NAME=""
}

# Dump recent ENFORCEMENT / DENY / AUDIT lines from the current enforce log.
show_audit_tail() {
    local n="${1:-30}"
    if [ -z "${ENFORCE_LOG:-}" ] || [ ! -f "$ENFORCE_LOG" ]; then
        echo -e "${Y}(no enforce log yet)${NC}"
        return 0
    fi
    echo -e "${B}--- recent enforcement / audit lines ---${NC}"
    grep -iE 'ENFORCEMENT|DENY|AUDIT|Enforcement:' "$ENFORCE_LOG" 2>/dev/null \
        | tail -n "$n" | sed 's/^/  /' \
        || echo -e "  ${D}(no DENY/AUDIT lines yet — check RUST_LOG / sudo env)${NC}"
}

# Optional asciinema wrapper. Usage: with_record <slug> -- <cmd...>
# If DEMO_RECORD=1 and asciinema is installed, records to recordings/<slug>.cast.
with_record() {
    local slug="$1"; shift
    [ "${1:-}" = "--" ] && shift
    if [ "${DEMO_RECORD:-0}" = "1" ] && command -v asciinema >/dev/null 2>&1; then
        mkdir -p "$RECORDINGS_DIR"
        local cast="$RECORDINGS_DIR/${slug}.cast"
        echo -e "${D}[record] $cast${NC}"
        # --idle-time-limit keeps long pauses from wasting tape
        asciinema rec --overwrite --idle-time-limit 3 -c "$*" "$cast"
    else
        "$@"
    fi
}

# Shared audit→live pattern used by RCE / exfil chapters.
# Args: <label> <container> <events.json> <attack-script-cmd> <legit-check-cmd> [cap2-legit-file] [legit-when]
# attack-script-cmd and legit-check-cmd are eval'd (so they can include args).
#
# legit-when (7th arg) controls WHICH phase shows the app's own HTTP endpoints:
#   live  (default) — show them under LIVE enforce (phase C). Use for targets
#                     whose in-process opens resolve to the profiled path
#                     (e.g. secretsvc /orders is clean under live enforce).
#   audit           — show them under AUDIT-ONLY (phase A). Use for vulnapp: its
#                     /health handler opens /app/config.txt from inside python,
#                     which the LSM path-resolution walks to a long host-overlay
#                     path that misses the profiled hash — a documented, pre-
#                     existing resolution quirk, not a policy gap. Under audit-only
#                     the endpoint still serves (deny is only logged), so the "app
#                     still works" beat lands honestly without a live false-positive.
audit_then_live() {
    local label="$1" name="$2" events="$3" attack="$4" legit_cmd="$5"
    local legit_file="${6:-/etc/hostname}"
    local legit_when="${7:-live}"

    if [ ! -r "$events" ]; then
        echo -e "${R}error:${NC} profile missing: $events"
        echo -e "  Re-run:  ./docs/demo/setup.sh   (or setup.sh without --skip-profile)"
        return 1
    fi

    echo -e "\n${B}[A] AUDIT-ONLY — attacks execute, each denial is logged${NC}"
    pause "Press Enter to start audit-only enforcement on $name..."
    start_enforce "$name" "$events" --audit-only || return 1
    pause "Press Enter to fire the attacks (expect EXECUTED / LEAKED, but logged)..."
    # shellcheck disable=SC2086
    eval "$attack" || true
    if [ "$legit_when" = "audit" ]; then
        echo
        echo -e "${B}The app's own work still serves (audit-only — nothing is blocked yet)${NC}"
        eval "$legit_cmd" || true
    fi
    echo
    show_audit_tail 40
    pause "Press Enter to stop audit-only and flip to LIVE blocking..."
    stop_enforce

    echo -e "\n${B}[B] LIVE ENFORCE — same attacks, now CONTAINED${NC}"
    start_enforce "$name" "$events" || return 1
    pause "Press Enter to fire the attacks again (expect CONTAINED / BLOCKED)..."
    # shellcheck disable=SC2086
    eval "$attack" || true
    echo
    bash "$DEMO_DIR/cap2-enforce.sh" "$name" "$legit_file" || true
    echo
    if [ "$legit_when" = "audit" ]; then
        echo -e "${D}NOTE: the app's REAL work is its in-process HTTP handlers, shown serving in${NC}"
        echo -e "${D}the [0] beats above (green). The 'read $legit_file via injected shell' line${NC}"
        echo -e "${D}is BLOCKED on purpose: that's a NEW process (docker exec sh+cat), not the${NC}"
        echo -e "${D}app — default-deny only permits the app's own opens. For this target the${NC}"
        echo -e "${D}app-still-works beat is shown under audit-only, because its /health handler${NC}"
        echo -e "${D}opens $legit_file in-process and under live enforce that open can hit a${NC}"
        echo -e "${D}host-overlay path-resolution quirk (documented, pre-existing — not a gap).${NC}"
    else
        echo -e "${B}[C] Legit traffic still works (no false positives)${NC}"
        eval "$legit_cmd" || true
    fi
    echo
    show_audit_tail 40
    pause "Press Enter to stop enforcement on $name..."
    stop_enforce
}

# count_events <events.json>  ->  echoes "net fs proc total"
count_events() {
    python3 - "$1" <<'PY' 2>/dev/null || echo "0 0 0 0"
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception:
    print("0 0 0 0"); raise SystemExit
n = len(d.get("network", [])); f = len(d.get("fs", [])); p = len(d.get("process", []))
print(n, f, p, n + f + p)
PY
}

# profile_one <name> <port> <out.json> <warmup-script>
# Learns a *tight* legit profile: starts the monitor FIRST, lets it attach, then
# drives the app's legit endpoints for the whole window, then validates the
# result is non-empty (an empty allow-list would block the app under enforce).
# Reads globals: PROFILE_SECS, REPO_ROOT, BIN.
profile_one() {
    local name="$1" port="$2" out="$3" warmup="$4"
    local secs="${PROFILE_SECS:-20}"
    echo -e "  ${B}profiling $name (${secs}s legit traffic)...${NC}"
    rm -f "$REPO_ROOT/ebpf-mon/final-events.json"

    # 1. monitor first — needs a couple seconds to attach before traffic flows
    ( cd "$REPO_ROOT/ebpf-mon" && RUST_LOG=warn "$BIN" --name "$name" ) >/dev/null 2>&1 &
    local mp=$!
    sleep 3

    # 1b. Restart the container WHILE the monitor is attached, so the app's
    #     INIT-time file footprint is captured — not just steady-state request
    #     handling. The interpreter opens all its modules/.so files ONCE at
    #     process start; if that happened before the monitor attached (as with a
    #     long-running container), the profile is starved down to the one file the
    #     request path touches, and default-deny enforcement then blocks the app's
    #     own startup. The monitor's restart tracking follows the new cgroup, so
    #     the fresh `python` init is recorded. Best-effort: if restart fails we
    #     still profile steady-state.
    echo -e "    ${D}restarting $name to capture app-init (interpreter/module) opens...${NC}"
    docker restart "$name" >/dev/null 2>&1 || true
    # Wait until the app answers again so the restart's init is seen and the
    # warmup traffic below isn't fired into a still-booting container.
    for _ in $(seq 1 40); do curl -sf -m 1 "http://127.0.0.1:$port/" >/dev/null 2>&1 && break; sleep 0.25; done

    # 2. drive legit traffic for the whole monitor window (warmup honors WARMUP_SECS)
    WARMUP_SECS="$secs" bash "$warmup" "127.0.0.1:$port" --warmup >/dev/null 2>&1 || true
    sleep 1

    # 3. stop + flush
    kill -INT "$mp" 2>/dev/null || true
    wait "$mp" 2>/dev/null || true

    if [ ! -f "$REPO_ROOT/ebpf-mon/final-events.json" ]; then
        echo -e "  ${R}warn${NC} no final-events.json produced for $name"
        return 1
    fi
    cp "$REPO_ROOT/ebpf-mon/final-events.json" "$out"

    # 4. validate — an empty profile means enforcement would block the app itself
    set -- $(count_events "$out")
    local net="${1:-0}" fs="${2:-0}" proc="${3:-0}" total="${4:-0}"
    if [ "$total" = "0" ]; then
        echo -e "  ${R}WARNING${NC} $name profile is EMPTY (net=0 fs=0 proc=0)."
        echo -e "  ${Y}Enforcing an empty profile will BLOCK the app itself.${NC}"
        echo -e "  ${D}The app may simply be idle — make sure warmup drives real traffic${NC}"
        echo -e "  ${D}(distinct requests) for the whole window, and verify counts are${NC}"
        echo -e "  ${D}non-zero before the talk.${NC}"
        return 1
    fi
    echo -e "  ${G}saved${NC} $out  ${D}(net=$net fs=$fs proc=$proc)${NC}"
    "$BIN" --compile "$out" 2>/dev/null \
        | grep -E 'emitted rules|file \(|exec:|network:' \
        | sed 's/^/    /' || true
    return 0
}

# Write / refresh docs/demo/.demo-env from current container state.
write_demo_env() {
    local workload_id vulnapp_id secretsvc_id
    workload_id="$(docker container inspect -f '{{.Id}}' "$WORKLOAD_NAME" 2>/dev/null || true)"
    vulnapp_id="$(docker container inspect -f '{{.Id}}' "$VULNAPP_NAME" 2>/dev/null || true)"
    secretsvc_id="$(docker container inspect -f '{{.Id}}' "$SECRETSVC_NAME" 2>/dev/null || true)"

    cat > "$ENV_FILE" <<EOF
# Generated by docs/demo/setup.sh — do not edit by hand.
# Sourced by docs/demo/run-demo.sh.
WORKLOAD_NAME=$WORKLOAD_NAME
WORKLOAD_ID=$workload_id
VULNAPP_NAME=$VULNAPP_NAME
VULNAPP_ID=$vulnapp_id
VULNAPP_PORT=$VULNAPP_PORT
VULNAPP_EVENTS=$DEMO_DIR/vulnapp-events.json
SECRETSVC_NAME=$SECRETSVC_NAME
SECRETSVC_ID=$secretsvc_id
SECRETSVC_PORT=$SECRETSVC_PORT
SECRETSVC_EVENTS=$DEMO_DIR/secretsvc-events.json
REPO_ROOT=$REPO_ROOT
BIN=$BIN
EOF
    echo -e "${G}[setup]${NC} wrote $ENV_FILE"
}
