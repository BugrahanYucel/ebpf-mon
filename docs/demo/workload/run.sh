#!/usr/bin/env bash
#
# Build and run the workload container, then print the command to attach the
# monitor to it.
#
#   ./run.sh                 # build + run detached
#   SLEEP_SECONDS=1 ./run.sh # faster event stream
#   EXTERNAL_NET=0 ./run.sh  # no outbound network (air-gapped hosts)
#
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE="${IMAGE:-ebpf-mon-workload:latest}"
NAME="${NAME:-ebpf-mon-workload}"
SLEEP_SECONDS="${SLEEP_SECONDS:-2}"
EXTERNAL_NET="${EXTERNAL_NET:-1}"

echo "[*] building image '$IMAGE'..."
docker build -t "$IMAGE" "$HERE"

echo "[*] (re)starting container '$NAME'..."
docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" \
    -e SLEEP_SECONDS="$SLEEP_SECONDS" \
    -e EXTERNAL_NET="$EXTERNAL_NET" \
    "$IMAGE" >/dev/null

CID="$(docker inspect -f '{{.Id}}' "$NAME")"
docker ps --filter "name=$NAME"

cat <<EOF

[+] Container '$NAME' is running.
    Full id: $CID

    Watch it work:      docker logs -f $NAME
    Attach the monitor: (from repo root)
        ./run-ebpf.sh --container $CID
    Stop it:            docker rm -f $NAME
EOF
