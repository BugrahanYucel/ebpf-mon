#!/usr/bin/env bash
#
# DEMO ORCHESTRATOR (REAL-INPUT EXPERIMENT) — a copy of run-demo.sh that drives
# chapters 2–6 from a REAL capture instead of the hand-written example-events.json.
#
# The idea you asked for: chapter 1 captures a live container, and chapters 2–6
# then compile THAT capture — so "chapter 2 compiles the real output of chapter 1"
# is literally true. Nothing here is pre-baked except chapter 5 (see the note in
# run_c5: you cannot capture a second, AppArmor-shaped input from the kernel, so
# the two-frontend convergence proof still uses illustrative twin inputs).
#
# This file NEVER touches run-demo.sh. Experiment freely.
#
# Prereq:  ./docs/demo/setup.sh   (containers up, profiles ready, binary built)
#
# Usage:
#   sudo -v && ./docs/demo/run-demo-real.sh                 # full talk, real input
#   ./docs/demo/run-demo-real.sh --capture vulnapp --secs 20
#   ./docs/demo/run-demo-real.sh --events /path/events.json # skip ch1, reuse a capture
#   ./docs/demo/run-demo-real.sh --from 2                   # reuse last real-events.json
#   ./docs/demo/run-demo-real.sh --list
set -euo pipefail

DEMO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$DEMO_DIR/lib.sh"

FROM=1
LIST=0
DEMO_RECORD=0
CAPTURE_NAME=""            # which container chapter 1 monitors (default: workload)
CAPTURE_SECS=15           # how long chapter 1 monitors
# Where the real capture is pinned so chapters 2–6 all read the SAME file.
REAL_EVENTS="${REAL_EVENTS:-$DEMO_DIR/real-events.json}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --from)    FROM="$2"; shift 2 ;;
        --record)  DEMO_RECORD=1; shift ;;
        --list)    LIST=1; shift ;;
        --capture) CAPTURE_NAME="$2"; shift 2 ;;
        --secs)    CAPTURE_SECS="$2"; shift 2 ;;
        --events)  REAL_EVENTS="$(realpath -m "$2")"; shift 2 ;;
        -h|--help)
            cat <<'EOF'
DEMO ORCHESTRATOR (REAL-INPUT EXPERIMENT)

Chapters 2–6 compile a REAL capture instead of example-events.json.

Prereq:  ./docs/demo/setup.sh

Usage:
  ./docs/demo/run-demo-real.sh                     # capture in ch1, compile it in ch2–6
  ./docs/demo/run-demo-real.sh --capture vulnapp   # capture a different container
  ./docs/demo/run-demo-real.sh --secs 20           # longer capture window
  ./docs/demo/run-demo-real.sh --events FILE        # reuse an existing capture, skip ch1
  ./docs/demo/run-demo-real.sh --from 2             # reuse the last real-events.json
  ./docs/demo/run-demo-real.sh --list
EOF
            exit 0
            ;;
        *) echo "unknown arg: $1"; exit 1 ;;
    esac
done
export DEMO_RECORD

CHAPTERS=(
    "1|Monitor richness|Live eBPF capture — this becomes the compiler's input for ch2–6"
    "2|IR anatomy|Compile the REAL ch1 capture; one FILE / NETWORK / PROCESS rule"
    "3|Optimization passes|Watch each pass shrink the REAL rule set (OFF vs ON)"
    "4|One IR → two formats|Real IR lowered to AppArmor text AND BPF-LSM maps"
    "5|2×2 equivalence|Two frontends, one IR, two backends (illustrative twin inputs — see note)"
    "6|Friction report|Real IR: EXPRESSED / APPROXIMATED / DROPPED per backend"
    "7|RCE containment|vulnapp: audit-only then live block of post-exploitation"
    "8|Data exfiltration|secretsvc: audit-only then live block of secret loot + C2"
)

if [ "$LIST" = "1" ]; then
    echo "Chapters (real-input variant):"
    for entry in "${CHAPTERS[@]}"; do
        IFS='|' read -r n title blurb <<<"$entry"
        printf "  %s  %-22s  %s\n" "$n" "$title" "$blurb"
    done
    exit 0
fi

load_env || exit 1
CAPTURE_NAME="${CAPTURE_NAME:-$WORKLOAD_NAME}"

# Make sure the three containers are still up (setup used --restart unless-stopped).
ensure_container "$WORKLOAD_NAME"  || exit 1
ensure_container "$VULNAPP_NAME"   || exit 1
ensure_container "$SECRETSVC_NAME" || exit 1

# Prime sudo once so later escalations don't pause mid-chapter.
echo -e "${D}Priming sudo (one password prompt up front)...${NC}"
sudo -v || { echo -e "${R}error:${NC} sudo required for monitor/enforce chapters"; exit 1; }
( while true; do sleep 60; sudo -n true 2>/dev/null || exit; done ) &
SUDO_KEEPER=$!
trap 'stop_enforce >/dev/null 2>&1 || true; kill $SUDO_KEEPER 2>/dev/null || true' EXIT

# ── real-input helpers ──────────────────────────────────────────────────────

# Guard chapters 2–6: they need a real capture on disk. If chapter 1 was skipped
# (--from >1 or --events not given), fall back to the last capture and explain.
require_real_events() {
    if [ -r "$REAL_EVENTS" ]; then
        return 0
    fi
    # Fall back to whatever chapter 1 (or a prior run) last produced.
    local last="$REPO_ROOT/ebpf-mon/final-events.json"
    if [ -r "$last" ]; then
        cp "$last" "$REAL_EVENTS"
        echo -e "${Y}note:${NC} using last capture $last as real input."
        return 0
    fi
    echo -e "${R}error:${NC} no real capture found ($REAL_EVENTS)."
    echo -e "  Run chapter 1 first:  ./docs/demo/run-demo-real.sh --from 1"
    echo -e "  or point at a file :  ./docs/demo/run-demo-real.sh --events <events.json>"
    return 1
}

echo
echo -e "${C}${BOLD}=== ebpf-mon stage demo (REAL INPUT) ===${NC}"
echo -e "${D}Chapters 2–6 compile a live capture, not example-events.json.${NC}"
echo -e "${D}Capture target: $CAPTURE_NAME (${CAPTURE_SECS}s)  →  $REAL_EVENTS${NC}"
echo -e "${D}Starting at chapter $FROM. Press Enter between chapters.${NC}"
if [ "$DEMO_RECORD" = "1" ]; then
    if command -v asciinema >/dev/null 2>&1; then
        echo -e "${D}Recording ON → $RECORDINGS_DIR/<chapter>.cast${NC}"
        mkdir -p "$RECORDINGS_DIR"
    else
        echo -e "${Y}--record set but asciinema not installed; continuing without recording.${NC}"
        DEMO_RECORD=0; export DEMO_RECORD
    fi
fi

# ── chapter runners ─────────────────────────────────────────────────────────

run_c1() {
    chapter 1 "Monitor richness" \
        "Attach to $CAPTURE_NAME for ~${CAPTURE_SECS}s. This capture feeds chapters 2–6."
    pause "Press Enter to start monitoring..."
    with_record c1-monitor -- \
        sudo env "PATH=$PATH" bash "$DEMO_DIR/cap1-monitor.sh" "$CAPTURE_NAME" "$CAPTURE_SECS"
    # Pin the fresh capture so every later chapter reads the SAME real input.
    if [ -r "$REPO_ROOT/ebpf-mon/final-events.json" ]; then
        cp "$REPO_ROOT/ebpf-mon/final-events.json" "$REAL_EVENTS"
        echo -e "\n${G}pinned real capture${NC} → $REAL_EVENTS ${D}($(count_events "$REAL_EVENTS"))${NC}"
    else
        echo -e "\n${Y}warning:${NC} no capture produced; chapters 2–6 will reuse the last one."
    fi
    echo -e "${D}Talking point: this rich stream is the compiler's source language.${NC}"
}

run_c2() {
    require_real_events || return 1
    chapter 2 "IR anatomy (REAL)" \
        "Compile the ch1 capture and print one FILE / NETWORK / PROCESS rule."
    pause "Press Enter to show the IR..."
    with_record c2-ir -- bash "$DEMO_DIR/cap3-ir.sh" "$REAL_EVENTS"
}

run_c3() {
    require_real_events || return 1
    chapter 3 "Optimization passes (REAL)" \
        "Per-pass reduction on the real rule set, then A/B: --no-optimize vs optimized."
    pause "Press Enter to run the optimizer..."
    with_record c3-optimize -- bash "$DEMO_DIR/cap5-optimize.sh" "$REAL_EVENTS"
}

run_c4() {
    require_real_events || return 1
    chapter 4 "One IR → two formats (REAL)" \
        "The real IR lowered to AppArmor text AND a BPF-LSM map plan."
    pause "Press Enter to transform..."
    with_record c4-transform -- bash "$DEMO_DIR/cap4-transform.sh" "$REAL_EVENTS"
}

run_c5() {
    chapter 5 "2×2 equivalence (illustrative inputs)" \
        "Two frontends converge; one IR lowers to two backends; verdict table + 3 divergences."
    echo -e "${Y}NOTE:${NC} this is the one chapter that CANNOT run purely from the live"
    echo -e "${D}capture. The 2×2 needs a SECOND source format (an AppArmor profile) that${NC}"
    echo -e "${D}means the same thing. AppArmor is enabled here, but the only way to LEARN a${NC}"
    echo -e "${D}profile from observed behavior is the INTERACTIVE aa-genprof/aa-logprof${NC}"
    echo -e "${D}(they prompt Allow/Deny per access), which can't run unattended mid-talk —${NC}"
    echo -e "${D}and you can't read a loaded profile back out of the kernel either. So the${NC}"
    echo -e "${D}twin inputs here are illustrative. The REAL direction (capture → IR → emitted${NC}"
    echo -e "${D}AppArmor) is exactly chapter 4 above; the reverse (AppArmor → IR) convergence${NC}"
    echo -e "${D}is asserted by the pipeline_2x2 test suite.${NC}"
    pause "Press Enter to run the cross-format demo..."
    with_record c5-2x2 -- bash "$DEMO_DIR/cap6-2x2.sh"
}

run_c6() {
    require_real_events || return 1
    chapter 6 "Friction report (REAL)" \
        "Per-rule, per-backend on the real IR: EXPRESSED / APPROXIMATED / DROPPED."
    pause "Press Enter to generate the friction report..."
    with_record c6-friction -- bash "$DEMO_DIR/cap7-friction.sh" "$REAL_EVENTS"
}

run_c7() {
    chapter 7 "RCE containment (vulnapp)" \
        "Audit-only first (see what WOULD be denied), then live block of post-exploitation."
    local events="${VULNAPP_EVENTS:-$DEMO_DIR/vulnapp-events.json}"
    local attack="bash '$DEMO_DIR/cve/cve-demo.sh' '127.0.0.1:${VULNAPP_PORT}'"
    local legit="serving 127.0.0.1:${VULNAPP_PORT} / liveness; serving 127.0.0.1:${VULNAPP_PORT} /health 'app reads /app/config.txt in-process'"
    # legit-when=audit: /health opens /app/config.txt from inside python; the LSM
    # path walk resolves that in-process open to a host-overlay path that misses
    # the profiled hash (documented resolution quirk). Show "app still works"
    # under audit-only; the live docker-exec read still resolves and stays OK.
    audit_then_live "RCE" "$VULNAPP_NAME" "$events" "$attack" "$legit" "/app/config.txt" "audit"
}

run_c8() {
    chapter 8 "Data exfiltration (secretsvc)" \
        "Audit-only first, then live block of secret loot + C2 egress. /orders stays up."
    local events="${SECRETSVC_EVENTS:-$DEMO_DIR/secretsvc-events.json}"
    local attack="CONTAINER='$SECRETSVC_NAME' bash '$DEMO_DIR/exfil-demo.sh' '127.0.0.1:${SECRETSVC_PORT}'"
    local legit="serving 127.0.0.1:${SECRETSVC_PORT} / liveness; serving 127.0.0.1:${SECRETSVC_PORT} /orders 'app reads /data/orders.json in-process'"
    audit_then_live "EXFIL" "$SECRETSVC_NAME" "$events" "$attack" "$legit" "/data/orders.json"
}

# ── dispatch ────────────────────────────────────────────────────────────────

for entry in "${CHAPTERS[@]}"; do
    IFS='|' read -r n title blurb <<<"$entry"
    if [ "$n" -lt "$FROM" ]; then
        continue
    fi
    case "$n" in
        1) run_c1 ;;
        2) run_c2 ;;
        3) run_c3 ;;
        4) run_c4 ;;
        5) run_c5 ;;
        6) run_c6 ;;
        7) run_c7 ;;
        8) run_c8 ;;
    esac
    if [ "$n" -lt 8 ]; then
        pause "Chapter $n done. Press Enter for chapter $((n+1))..."
    fi
done

echo
hr
echo -e "${G}${BOLD}Demo complete (real input). Thanks.${NC}"
hr
echo -e "${D}Real capture used: $REAL_EVENTS${NC}"
echo -e "${D}Recordings (if any): $RECORDINGS_DIR/${NC}"
