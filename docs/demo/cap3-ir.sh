#!/usr/bin/env bash
#
# CAPABILITY 3 — THE IR (anatomy of a neutral rule).
# Laptop-safe: no kernel, no root, no container.
#
# Story beat: "After I explain the IR, I show its structure." Compiles raw
# events into the normalized IR and prints ONE file rule and ONE network rule,
# annotated WHO / WHAT / WHICH-OP / VERDICT — the four fields every backend
# reads. This is the 'source-and-target-independent' representation.
#
# Usage:  ./docs/demo/cap3-ir.sh [events.json]
set -euo pipefail
# Resolve the (optional) events path against the caller's CWD BEFORE we cd,
# so `./docs/demo/cap3-ir.sh ../../ebpf-mon/events.json` works from anywhere.
if [ "${1:-}" != "" ]; then EVENTS="$(realpath -m "$1")"; fi
cd "$(dirname "$0")/../.."
EVENTS="${EVENTS:-docs/demo/example-events.json}"
[ -r "$EVENTS" ] || { echo "error: events file not found/readable: $EVENTS" >&2; exit 1; }
IR_TMP="$(mktemp --suffix=-ir.json)"
trap 'rm -f "$IR_TMP"' EXIT

if [ -x target/release/ebpf-mon ]; then BIN=(target/release/ebpf-mon); else BIN=(cargo run -q -p ebpf-mon --); fi
C='\033[1;36m'; D='\033[0;90m'; NC='\033[0m'

echo -e "${C}=== The IR: one observation, four fields ===${NC}"
"${BIN[@]}" --compile "$EVENTS" --emit-json "$IR_TMP" >/dev/null 2>&1

python3 - "$IR_TMP" <<'PY'
import json, sys
rules = json.load(open(sys.argv[1]))

def show(r, title):
    obj = r["object"]
    kind = next(iter(obj))
    who  = r["subject"]
    print(f"\n  \033[1;33m{title}\033[0m  (rule id {r['id']})")
    # WHO
    cont = who.get("container"); binp = who.get("binary"); uid = who.get("uid")
    print(f"    WHO   subject : container={cont}  binary={binp}  uid={uid}")
    # WHAT
    print(f"    WHAT  object  : {kind} -> {json.dumps(obj[kind])}")
    # OPERATION
    print(f"    OP    action  : {r['action']}")
    # VERDICT
    print(f"    VERD  verdict : {r['verdict']}")

file_rule = next((r for r in rules if "File" in r["object"]), None)
net_rule  = next((r for r in rules if "Network" in r["object"]), None)
proc_rule = next((r for r in rules if "Process" in r["object"]), None)
if file_rule: show(file_rule, "FILE rule")
if net_rule:  show(net_rule,  "NETWORK rule")
if proc_rule: show(proc_rule, "PROCESS rule")

print(f"\n  \033[0;90mTotal rules in IR: {len(rules)}. "
      f"No hook, no map, no profile syntax — just WHO/WHAT/OP/VERDICT.\033[0m")
PY

echo -e "\n${D}This same IR is what every optimization pass and every backend consumes.${NC}"
