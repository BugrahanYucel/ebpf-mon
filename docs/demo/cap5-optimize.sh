#!/usr/bin/env bash
#
# CAPABILITY 5 — OPTIMIZATION PASSES (reduce the rule set).
# Laptop-safe: no kernel, no root, no container.
#
# Story beat: "The IR is where you get to be smart." Shows each pass shrinking
# the rule set, then an A/B: optimizer OFF vs ON. On the sample profile the
# headline is prefix-generalization collapsing a cluster of sibling files into
# a couple of directory rules.
#
# Usage:  ./docs/demo/cap5-optimize.sh [events.json]
set -euo pipefail
# Resolve the (optional) events path against the caller's CWD BEFORE we cd.
if [ "${1:-}" != "" ]; then EVENTS="$(realpath -m "$1")"; fi
cd "$(dirname "$0")/../.."
EVENTS="${EVENTS:-docs/demo/example-events.json}"
[ -r "$EVENTS" ] || { echo "error: events file not found/readable: $EVENTS" >&2; exit 1; }
if [ -x target/release/ebpf-mon ]; then BIN=(target/release/ebpf-mon); else BIN=(cargo run -q -p ebpf-mon --); fi
C='\033[1;36m'; Y='\033[1;33m'; D='\033[0;90m'; NC='\033[0m'
hr(){ echo -e "${D}------------------------------------------------------------${NC}"; }

echo -e "${C}=== Optimization: watch each pass reduce the rule set ===${NC}"
RUST_LOG=info "${BIN[@]}" --compile "$EVENTS" 2>&1 \
  | grep -iE 'translated|canonical|dedup|generaliz|prefix|subsum|conflict|linker|emitted rules' \
  | sed -E 's/.*ebpf_mon[^]]*\] ?//; s/.*INFO *//' \
  | sed 's/^/    /'

echo
hr; echo -e "${Y}A/B — optimizer OFF vs ON:${NC}"; hr
echo -n "    --no-optimize : "; "${BIN[@]}" --compile "$EVENTS" --no-optimize 2>/dev/null | grep -iE 'emitted rules'
echo -n "    optimized     : "; "${BIN[@]}" --compile "$EVENTS"               2>/dev/null | grep -iE 'emitted rules'
hr
echo -e "${D}Fewer rules = smaller maps, faster lookups, and a policy a human can read.${NC}"
