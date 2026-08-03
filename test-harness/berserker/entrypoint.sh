#!/bin/sh
# Berserker entrypoint: pick a workload by name (TOML) or run a script (.ber).
#
#   WORKLOAD=<name>   -> runs /workloads/<name>.toml   (default: processes)
#   SCRIPT=<path>     -> runs `berserker -f <path>`    (takes precedence)
#   any extra args are forwarded to berserker.
set -eu

if [ -n "${SCRIPT:-}" ]; then
    echo "[berserker] script mode: $SCRIPT" >&2
    exec berserker -f "$SCRIPT" "$@"
fi

WORKLOAD="${WORKLOAD:-processes}"
CONFIG="/workloads/${WORKLOAD}.toml"
if [ ! -f "$CONFIG" ]; then
    echo "[berserker] unknown workload '$WORKLOAD'. Available workloads:" >&2
    for f in /workloads/*.toml; do
        [ -e "$f" ] || continue
        name=$(basename "$f" .toml)
        echo "  - $name" >&2
    done
    for f in /workloads/*.ber; do
        [ -e "$f" ] || continue
        echo "  - $(basename "$f")  (use SCRIPT=$f)" >&2
    done
    exit 1
fi

echo "[berserker] workload=$WORKLOAD config=$CONFIG" >&2
exec berserker -c "$CONFIG" "$@"
