#!/usr/bin/env bash
#
# CAPABILITY 7 — THE FRICTION REPORT (the tool documents its own envelope).
# Laptop-safe: no kernel, no root, no container.
#
# Story beat: honesty slide. For every rule and every backend, the report says
# EXPRESSED / APPROXIMATED / DROPPED, with the reason. This is the novel bit:
# we don't pretend the translation is lossless — we generate the loss inventory.
#
# Usage:  ./docs/demo/cap7-friction.sh [events.json]
set -euo pipefail
# Resolve the (optional) events path against the caller's CWD BEFORE we cd.
if [ "${1:-}" != "" ]; then EVENTS="$(realpath -m "$1")"; fi
cd "$(dirname "$0")/../.."
EVENTS="${EVENTS:-docs/demo/example-events.json}"
[ -r "$EVENTS" ] || { echo "error: events file not found/readable: $EVENTS" >&2; exit 1; }
if [ -x target/release/ebpf-mon ]; then BIN=(target/release/ebpf-mon); else BIN=(cargo run -q -p ebpf-mon --); fi
C='\033[1;36m'; NC='\033[0m'

echo -e "${C}=== Friction report: what each backend can and cannot express ===${NC}"
"${BIN[@]}" --compile "$EVENTS" --friction-report 2>/dev/null | sed -n '/FRICTION REPORT/,$p'
