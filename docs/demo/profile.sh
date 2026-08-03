#!/usr/bin/env bash
#
# MONITOR / PROFILE helper — capture a container's behavior into a profile JSON
# that you can then --compile and --enforce.
#
# Usage:  sudo ./docs/demo/profile.sh <container-name> [seconds] [out.json]
#
# While it runs, exercise the container's real workload (hit its endpoints, let
# it talk to its DB, etc.) so the profile captures everything it legitimately
# needs — otherwise enforcement will later deny the un-exercised paths/endpoints.
set -euo pipefail
cd "$(dirname "$0")/../.."   # repo root

CONTAINER="${1:?usage: profile.sh <container-name> [seconds] [out.json]}"
SECONDS_TO_RUN="${2:-20}"
OUT="${3:-docs/demo/${CONTAINER}-events.json}"

if [ "$(id -u)" -ne 0 ]; then echo "run as root (sudo)"; exit 1; fi
BIN="target/release/ebpf-mon"
[ -x "$BIN" ] || { echo "build first: (cd ebpf-mon && cargo build --release)"; exit 1; }

echo "[profile] monitoring '$CONTAINER' for ${SECONDS_TO_RUN}s -> $OUT"
echo "[profile] >>> exercise the container's workload NOW <<<"

# ebpf-mon writes its profile on exit; give it the container and a time box.
( cd ebpf-mon && RUST_LOG=info "../$BIN" --name "$CONTAINER" ) &
PID=$!
sleep "$SECONDS_TO_RUN"
kill -INT "$PID" 2>/dev/null || true
wait "$PID" 2>/dev/null || true

# ebpf-mon emits final-events.json in its working dir (ebpf-mon/).
if [ -f "ebpf-mon/final-events.json" ]; then
    cp "ebpf-mon/final-events.json" "$OUT"
    echo "[profile] saved $OUT"
    "$BIN" --compile "$OUT" 2>/dev/null | grep -E 'emitted rules|file \(|exec:|network:' || true
else
    echo "[profile] WARN: expected ebpf-mon/final-events.json was not produced"
fi
