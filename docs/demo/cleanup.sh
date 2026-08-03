#!/usr/bin/env bash
#
# DEMO CLEANUP — tear the pipeline down so you can restart from scratch.
#
# Default: stop any running enforcement, remove the 3 demo containers, and
# delete generated state (.demo-env + profiled *-events.json). Recordings and
# built images are KEPT unless you ask.
#
# Usage:
#   ./docs/demo/cleanup.sh                 # containers + generated state
#   ./docs/demo/cleanup.sh --keep-events   # keep the profiled events JSON
#   ./docs/demo/cleanup.sh --recordings    # also delete docs/demo/recordings/
#   ./docs/demo/cleanup.sh --images        # also remove the 3 built images
#   ./docs/demo/cleanup.sh --all           # everything (images + recordings)
#
# After cleanup, rebuild with:  ./docs/demo/setup.sh
set -uo pipefail

DEMO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$DEMO_DIR/lib.sh"

RM_IMAGES=0
RM_RECORDINGS=0
KEEP_EVENTS=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --images)      RM_IMAGES=1; shift ;;
        --recordings)  RM_RECORDINGS=1; shift ;;
        --keep-events) KEEP_EVENTS=1; shift ;;
        --all)         RM_IMAGES=1; RM_RECORDINGS=1; shift ;;
        -h|--help)
            cat <<'EOF'
DEMO CLEANUP — tear the pipeline down so you can restart from scratch.

  ./docs/demo/cleanup.sh                 # containers + generated state
  ./docs/demo/cleanup.sh --keep-events   # keep the profiled events JSON
  ./docs/demo/cleanup.sh --recordings    # also delete docs/demo/recordings/
  ./docs/demo/cleanup.sh --images        # also remove the 3 built images
  ./docs/demo/cleanup.sh --all           # everything (images + recordings)

Rebuild with:  ./docs/demo/setup.sh
EOF
            exit 0
            ;;
        *) echo "unknown arg: $1"; exit 1 ;;
    esac
done

echo -e "${C}${BOLD}=== ebpf-mon demo cleanup ===${NC}"

# 1. Stop any background enforcement the orchestrator may have left running.
echo -e "${B}[1] Stop any running enforcement${NC}"
if pgrep -af -- 'ebpf-mon .*--enforce' >/dev/null 2>&1; then
    sudo pkill -INT -f 'ebpf-mon .*--enforce' 2>/dev/null || true
    sleep 1
    sudo pkill -TERM -f 'ebpf-mon .*--enforce' 2>/dev/null || true
    echo -e "  ${G}ok${NC} signalled enforce process(es)"
else
    echo -e "  ${D}none running${NC}"
fi

# 2. Remove the demo containers.
echo -e "${B}[2] Remove containers${NC}"
for name in "$WORKLOAD_NAME" "$VULNAPP_NAME" "$SECRETSVC_NAME"; do
    if docker container inspect "$name" >/dev/null 2>&1; then
        docker rm -f "$name" >/dev/null 2>&1 && echo -e "  ${G}removed${NC} $name"
    else
        echo -e "  ${D}absent${NC} $name"
    fi
done

# 3. Delete generated state.
echo -e "${B}[3] Delete generated state${NC}"
rm -f "$ENV_FILE" && echo -e "  ${G}rm${NC} $(basename "$ENV_FILE")" || true
if [ "$KEEP_EVENTS" = "0" ]; then
    rm -f "$DEMO_DIR/vulnapp-events.json" "$DEMO_DIR/secretsvc-events.json" \
        && echo -e "  ${G}rm${NC} profiled *-events.json"
    # The monitor's scratch outputs in the crate dir (not the committed sample).
    rm -f "$REPO_ROOT/ebpf-mon/final-events.json" "$REPO_ROOT/ebpf-mon/events.json" 2>/dev/null || true
else
    echo -e "  ${D}kept${NC} profiled events (--keep-events)"
fi

# 4. Optional: recordings.
if [ "$RM_RECORDINGS" = "1" ]; then
    echo -e "${B}[4] Delete recordings${NC}"
    rm -rf "$RECORDINGS_DIR" && echo -e "  ${G}rm${NC} $(basename "$RECORDINGS_DIR")/"
fi

# 5. Optional: images.
if [ "$RM_IMAGES" = "1" ]; then
    echo -e "${B}[5] Remove built images${NC}"
    for img in ebpf-mon-workload:latest vulnapp:latest secretsvc:latest; do
        docker image inspect "$img" >/dev/null 2>&1 \
            && docker rmi "$img" >/dev/null 2>&1 && echo -e "  ${G}rmi${NC} $img" \
            || echo -e "  ${D}absent${NC} $img"
    done
fi

echo
echo -e "${G}${BOLD}Clean.${NC}  Rebuild with:  ${G}./docs/demo/setup.sh${NC}"
