#!/usr/bin/env bash
#
# DEMO ORCHESTRATOR — interactive, press-Enter-to-advance stage runner.
#
# Prereq:  ./docs/demo/setup.sh   (containers up, profiles ready, binary built)
#
# Usage:
#   ./docs/demo/run-demo.sh              # full talk, pause between chapters
#   ./docs/demo/run-demo.sh --from 7     # jump to chapter 7 (RCE)
#   ./docs/demo/run-demo.sh --record     # wrap each chapter in asciinema
#   ./docs/demo/run-demo.sh --list       # list chapters and exit
#
# Standalone cap*.sh / cve-demo.sh / exfil-demo.sh scripts are still available
# if anything here fails — this file just sequences them with pauses.
set -euo pipefail

DEMO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$DEMO_DIR/lib.sh"

FROM=1
LIST=0
DEMO_RECORD=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --from)   FROM="$2"; shift 2 ;;
        --record) DEMO_RECORD=1; shift ;;
        --list)   LIST=1; shift ;;
        -h|--help)
            cat <<'EOF'
DEMO ORCHESTRATOR — interactive, press-Enter-to-advance stage runner.

Prereq:  ./docs/demo/setup.sh

Usage:
  ./docs/demo/run-demo.sh              # full talk, pause between chapters
  ./docs/demo/run-demo.sh --from 7     # jump to chapter 7 (RCE)
  ./docs/demo/run-demo.sh --record     # wrap each chapter in asciinema
  ./docs/demo/run-demo.sh --list       # list chapters and exit
EOF
            exit 0
            ;;
        *) echo "unknown arg: $1"; exit 1 ;;
    esac
done
export DEMO_RECORD

CHAPTERS=(
    "1|Monitor richness|Live eBPF capture of the workload container — every field resolved"
    "2|IR anatomy|One observation, four fields: WHO / WHAT / OP / VERDICT"
    "3|Optimization passes|Watch each pass shrink the rule set (OFF vs ON)"
    "4|One IR → two formats|Same IR lowered to AppArmor text AND BPF-LSM maps"
    "5|2×2 equivalence|Two frontends, one IR, two backends — concrete verdict table"
    "6|Friction report|Honest envelope: EXPRESSED / APPROXIMATED / DROPPED"
    "7|RCE containment|vulnapp: audit-only then live block of post-exploitation"
    "8|Data exfiltration|secretsvc: audit-only then live block of secret loot + C2"
)

if [ "$LIST" = "1" ]; then
    echo "Chapters:"
    for entry in "${CHAPTERS[@]}"; do
        IFS='|' read -r n title blurb <<<"$entry"
        printf "  %s  %-22s  %s\n" "$n" "$title" "$blurb"
    done
    exit 0
fi

load_env || exit 1

# Make sure the three containers are still up (setup used --restart unless-stopped).
ensure_container "$WORKLOAD_NAME"  || exit 1
ensure_container "$VULNAPP_NAME"   || exit 1
ensure_container "$SECRETSVC_NAME" || exit 1

# Prime sudo once so later escalations don't pause mid-chapter.
echo -e "${D}Priming sudo (one password prompt up front)...${NC}"
sudo -v || { echo -e "${R}error:${NC} sudo required for monitor/enforce chapters"; exit 1; }
# Keep the sudo ticket alive for the length of the talk.
( while true; do sleep 60; sudo -n true 2>/dev/null || exit; done ) &
SUDO_KEEPER=$!
trap 'stop_enforce >/dev/null 2>&1 || true; kill $SUDO_KEEPER 2>/dev/null || true' EXIT

echo
echo -e "${C}${BOLD}=== ebpf-mon stage demo ===${NC}"
echo -e "${D}Containers: $WORKLOAD_NAME / $VULNAPP_NAME / $SECRETSVC_NAME${NC}"
echo -e "${D}Starting at chapter $FROM. Press Enter between chapters.${NC}"
if [ "$DEMO_RECORD" = "1" ]; then
    if command -v asciinema >/dev/null 2>&1; then
        echo -e "${D}Recording ON → $RECORDINGS_DIR/<chapter>.cast${NC}"
        mkdir -p "$RECORDINGS_DIR"
    else
        echo -e "${Y}--record set but asciinema not installed; continuing without recording.${NC}"
        echo -e "${D}  Install:  pipx install asciinema   (or your distro package)${NC}"
        DEMO_RECORD=0; export DEMO_RECORD
    fi
fi

# ── chapter runners ─────────────────────────────────────────────────────────

run_c1() {
    chapter 1 "Monitor richness" \
        "Attach to $WORKLOAD_NAME for ~12s. Look for resolved paths, argv, endpoints, cgroup."
    pause "Press Enter to start monitoring..."
    with_record c1-monitor -- \
        sudo env "PATH=$PATH" bash "$DEMO_DIR/cap1-monitor.sh" "$WORKLOAD_NAME" 12
    echo -e "\n${D}Talking point: this rich stream is the compiler's source language.${NC}"
}

run_c2() {
    chapter 2 "IR anatomy" \
        "Compile example-events.json and print one FILE / NETWORK / PROCESS rule."
    pause "Press Enter to show the IR..."
    with_record c2-ir -- \
        bash "$DEMO_DIR/cap3-ir.sh" "$DEMO_DIR/example-events.json"
}

run_c3() {
    chapter 3 "Optimization passes" \
        "Per-pass reduction, then A/B: --no-optimize vs optimized."
    pause "Press Enter to run the optimizer..."
    with_record c3-optimize -- \
        bash "$DEMO_DIR/cap5-optimize.sh" "$DEMO_DIR/example-events.json"
}

run_c4() {
    chapter 4 "One IR → two formats" \
        "Same IR lowered to AppArmor text AND a BPF-LSM map plan."
    pause "Press Enter to transform..."
    with_record c4-transform -- \
        bash "$DEMO_DIR/cap4-transform.sh" "$DEMO_DIR/example-events.json"
}

run_c5() {
    chapter 5 "2×2 equivalence" \
        "Two frontends converge; one IR lowers to two backends; verdict table + 3 divergences."
    pause "Press Enter to run the cross-format demo..."
    with_record c5-2x2 -- \
        bash "$DEMO_DIR/cap6-2x2.sh"
}

run_c6() {
    chapter 6 "Friction report" \
        "Per-rule, per-backend: EXPRESSED / APPROXIMATED / DROPPED."
    pause "Press Enter to generate the friction report..."
    with_record c6-friction -- \
        bash "$DEMO_DIR/cap7-friction.sh" "$DEMO_DIR/example-events.json"
}

run_c7() {
    chapter 7 "RCE containment (vulnapp)" \
        "Audit-only first (see what WOULD be denied), then live block of post-exploitation."
    local events="${VULNAPP_EVENTS:-$DEMO_DIR/vulnapp-events.json}"
    local attack="bash '$DEMO_DIR/cve/cve-demo.sh' '127.0.0.1:${VULNAPP_PORT}'"
    local legit="serving 127.0.0.1:${VULNAPP_PORT} / liveness; serving 127.0.0.1:${VULNAPP_PORT} /health 'app reads /app/config.txt in-process'"
    # Recording the whole interactive chapter is awkward (nested pauses); record
    # is most useful for C1–C6. Still honour --record by wrapping if set.
    if [ "${DEMO_RECORD:-0}" = "1" ] && command -v asciinema >/dev/null 2>&1; then
        echo -e "${D}[record] note: C7/C8 pauses still need your Enter; cast captures the whole chapter${NC}"
    fi
    # legit-when=audit: vulnapp's /health opens /app/config.txt from inside
    # python; the LSM path walk resolves that in-process open to a host-overlay
    # path that misses the profiled hash (documented resolution quirk). Show the
    # "app still works" beat under audit-only so it lands honestly; the live
    # docker-exec read of /app/config.txt still resolves correctly and stays OK.
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
echo -e "${G}${BOLD}Demo complete. Thanks.${NC}"
hr
echo -e "${D}Recordings (if any): $RECORDINGS_DIR/${NC}"
echo -e "${D}Standalone scripts remain under docs/demo/ for recovery.${NC}"
