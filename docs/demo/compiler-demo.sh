#!/usr/bin/env bash
#
# COMPILER DEMO (no kernel, no root, no container).
#
# Tells the whole "one IR, many targets" story on a laptop, safely, live:
#   1. optimization: raw events  -> minimal rule set (per-pass reduction)
#   2. A/B:          --no-optimize vs optimized rule counts
#   3. friction:     what each backend can/can't express (generated report)
#   4. 2x2 proof:    two frontends -> one IR -> two backends (cargo test)
#   5. artifacts:    the emitted AppArmor profile and the optimized IR JSON
#
# Usage:  ./docs/demo/compiler-demo.sh [path/to/events.json]
set -euo pipefail
cd "$(dirname "$0")/../.."   # repo root

EVENTS="${1:-docs/demo/example-events.json}"
AA_OUT="docs/demo/example.apparmor"
IR_OUT="docs/demo/example-ir.json"

# Prefer a prebuilt release binary; fall back to `cargo run`.
if [ -x "target/release/ebpf-mon" ]; then
    BIN=(target/release/ebpf-mon)
else
    BIN=(cargo run -q -p ebpf-mon --)
fi

C_HEAD='\033[1;36m'; C_DIM='\033[0;90m'; NC='\033[0m'
say()  { echo -e "\n${C_HEAD}=== $* ===${NC}"; }
hr()   { echo -e "${C_DIM}------------------------------------------------------------${NC}"; }
pause(){ echo; read -rp $'\033[1;33m[enter to continue]\033[0m ' _ </dev/tty 2>/dev/null || true; }

say "INPUT: raw profiled events"
python3 -c "import json;d=json.load(open('$EVENTS'));print('  '+', '.join(f'{k}={len(v)}' for k,v in d.items() if isinstance(v,list)))" 2>/dev/null || true
pause

say "1) OPTIMIZATION — watch each pass reduce the rule set"
RUST_LOG=info "${BIN[@]}" --compile "$EVENTS" 2>&1 \
  | grep -E 'Translated|canonicalize|dedup|generalize|prefix-generalize|subsum|link|emitted rules|file \(|exec:|network:' || true
pause

say "2) A/B — optimizer OFF vs ON"
hr; echo "  --no-optimize:"
"${BIN[@]}" --compile "$EVENTS" --no-optimize 2>/dev/null | grep -E 'emitted rules' | sed 's/^/    /'
echo "  optimized:"
"${BIN[@]}" --compile "$EVENTS" 2>/dev/null | grep -E 'emitted rules' | sed 's/^/    /'
hr
pause

say "3) FRICTION REPORT — what each backend can/can't express"
"${BIN[@]}" --compile "$EVENTS" --friction-report 2>/dev/null | sed -n '/FRICTION REPORT/,$p'
pause

say "4) 2x2 EQUIVALENCE PROOF — two frontends -> one IR -> two backends"
cargo test -q -p ebpf-mon-common --features user --test pipeline_2x2 2>&1 \
  | grep -E 'running|test result' || true
pause

say "5) ARTIFACTS — the same IR, lowered two ways"
"${BIN[@]}" --compile "$EVENTS" --emit-apparmor "$AA_OUT" --emit-json "$IR_OUT" >/dev/null 2>&1
hr; echo "  Emitted AppArmor profile ($AA_OUT):"; hr
sed 's/^/    /' "$AA_OUT"
hr; echo "  Optimized IR JSON ($IR_OUT): first rule"; hr
python3 -c "import json;d=json.load(open('$IR_OUT'));print(json.dumps(d[0],indent=2))" 2>/dev/null | sed 's/^/    /' || true
echo -e "\n${C_HEAD}Demo complete.${NC}"
