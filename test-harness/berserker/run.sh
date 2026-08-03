#!/usr/bin/env bash
# Build (once) and run a Berserker workload as a named container that ebpf-mon
# can target by name.
#
#   ./run.sh                      # default: processes workload
#   ./run.sh endpoints            # a specific TOML workload
#   ./run.sh syscalls-open
#   ./run.sh network              # privileged (adds NET_ADMIN + /dev/net/tun)
#   ./run.sh --script files.ber   # run a .ber script workload
#   ./run.sh <workload> --build   # force an image rebuild
#
# Stop with:  docker rm -f berserker-<workload>
set -euo pipefail
cd "$(dirname "$0")"

IMAGE="ebpf-mon/berserker:latest"

SCRIPT=""
WORKLOAD="processes"
FORCE_BUILD=0
args=("$@")
i=0
while [ $i -lt ${#args[@]} ]; do
    a="${args[$i]}"
    case "$a" in
        --script)
            i=$((i + 1)); SCRIPT="${args[$i]:?--script needs a filename in workloads/}" ;;
        --build) FORCE_BUILD=1 ;;
        *) WORKLOAD="$a" ;;
    esac
    i=$((i + 1))
done

if [ "$FORCE_BUILD" -eq 1 ] || ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "[run] building $IMAGE (first build pulls Fedora + compiles berserker; be patient)..."
    docker build -t "$IMAGE" .
fi

extra=()
env_args=(-e RUST_LOG=info)

if [ -n "$SCRIPT" ]; then
    NAME="berserker-script"
    env_args+=(-e "SCRIPT=/workloads/${SCRIPT}")
    label="script=${SCRIPT}"
else
    NAME="berserker-${WORKLOAD}"
    env_args+=(-e "WORKLOAD=${WORKLOAD}")
    label="workload=${WORKLOAD}"
    if [ "$WORKLOAD" = "network" ]; then
        extra=(--cap-add NET_ADMIN --device /dev/net/tun)
    fi
fi

docker rm -f "$NAME" >/dev/null 2>&1 || true
echo "[run] starting $NAME ($label)"
docker run -d --name "$NAME" "${env_args[@]}" "${extra[@]}" "$IMAGE"

echo "[run] container '$NAME' is up. Point ebpf-mon at it:"
echo "        sudo ./ebpf-mon --container $NAME"
echo "[run] logs:  docker logs -f $NAME"
echo "[run] stop:  docker rm -f $NAME"
