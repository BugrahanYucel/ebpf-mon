#!/usr/bin/env bash
#
# CAPABILITY 1 — eBPF GRANULAR MONITORING (the 'source language').
# NEEDS: root + a running container + a BPF-capable kernel.  Pre-record as backup.
#
# Story beat: right after the eBPF intro. We attach to the kernel and watch a
# container's real behavior with FULL context — resolved file paths, the exec'd
# binary, network endpoints, container id, uid. This rich, resolved stream is
# what makes a compiler frontend possible (syscall-number tools can't see this).
#
# Usage:  sudo ./docs/demo/cap1-monitor.sh <container-name> [seconds]
set -euo pipefail
cd "$(dirname "$0")/../.."

CONTAINER="${1:?usage: sudo cap1-monitor.sh <container-name> [seconds]}"
SECS="${2:-15}"
[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo)"; exit 1; }
BIN="target/release/ebpf-mon"
[ -x "$BIN" ] || { echo "build first: cargo build --release -p ebpf-mon"; exit 1; }
C='\033[1;36m'; Y='\033[1;33m'; D='\033[0;90m'; NC='\033[0m'

echo -e "${C}=== eBPF live monitoring: '$CONTAINER' for ${SECS}s ===${NC}"
echo -e "${Y}>>> exercise the workload NOW (hit its endpoints, let it reach its DB) <<<${NC}"

( cd ebpf-mon && RUST_LOG=info "../$BIN" --name "$CONTAINER" ) &
PID=$!
sleep "$SECS"
kill -INT "$PID" 2>/dev/null || true
wait "$PID" 2>/dev/null || true

RAW="ebpf-mon/final-events.json"
[ -f "$RAW" ] || { echo "no events captured ($RAW missing)"; exit 1; }

echo -e "\n${C}Captured raw events (this is the compiler's input):${NC}"
python3 - "$RAW" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
for k, v in d.items():
    if isinstance(v, list):
        print(f"  {k}: {len(v)} events")
# show one fully-resolved sample from whichever category is non-empty
for k, v in d.items():
    if isinstance(v, list) and v:
        print(f"\n  sample [{k}] — note the RESOLVED context:")
        print("   ", json.dumps(v[0], indent=2).replace("\n", "\n    "))
        break
PY
echo -e "\n${D}Full paths, binary identity, endpoints, container+uid — not just syscall numbers.${NC}"
