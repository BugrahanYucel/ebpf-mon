#!/bin/bash
#
# End-to-end demo: Profile -> Compile -> Enforce
#
# This script demonstrates the full compilation pipeline:
#   Phase 1: Start a test container and profile its behavior
#   Phase 2: Re-run with enforcement in audit-only mode
#   Phase 3: Re-run with active enforcement and test unauthorized access
#
# Usage:
#   sudo ./demo.sh              # Full demo (all 3 phases)
#   sudo ./demo.sh --phase 2    # Start from phase 2 (requires existing profile)
#
# Prerequisites:
#   - Docker installed and running
#   - BPF-LSM enabled kernel (check: cat /sys/kernel/security/lsm | grep bpf)
#   - Must be run as root (sudo)
#

set -e

# ─────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────

CONTAINER_NAME="ebpf-demo-nginx"
CONTAINER_IMAGE="nginx:alpine"
PROFILE_DURATION=15
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EBPF_BIN="$SCRIPT_DIR/target/release/ebpf-mon"
PROFILE_PATH="$SCRIPT_DIR/ebpf-mon/final-events.json"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

START_PHASE=1
EBPF_PID=""

# ─────────────────────────────────────────────────────────────
# Argument parsing
# ─────────────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
    case $1 in
        --phase) START_PHASE="$2"; shift 2 ;;
        --duration) PROFILE_DURATION="$2"; shift 2 ;;
        --container) CONTAINER_NAME="$2"; shift 2 ;;
        *) echo -e "${RED}Unknown option: $1${NC}"; exit 1 ;;
    esac
done

# ─────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────

banner() {
    echo ""
    echo -e "${BOLD}${GREEN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${GREEN}  $1${NC}"
    echo -e "${BOLD}${GREEN}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
}

info()  { echo -e "${BLUE}[INFO]${NC}  $1"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $1"; }
fail()  { echo -e "${RED}[FAIL]${NC}  $1"; exit 1; }
pause() {
    echo ""
    echo -e "${YELLOW}>>> Press ENTER to continue to the next phase...${NC}"
    read -r < /dev/tty 2>/dev/null || sleep 2
}

cleanup_container() {
    if docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
        info "Removing existing container: $CONTAINER_NAME"
        docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
    fi
}

# Kill any running ebpf-mon process we started, by PID
stop_ebpf() {
    local pid="$1"
    [ -z "$pid" ] && return 0

    kill -INT "$pid" 2>/dev/null || true

    for _ in $(seq 1 8); do
        if ! kill -0 "$pid" 2>/dev/null; then
            wait_for_bpf_cleanup
            return 0
        fi
        sleep 1
    done

    warn "Graceful shutdown timed out, sending SIGKILL..."
    kill -KILL "$pid" 2>/dev/null || true
    sleep 2
    wait_for_bpf_cleanup
}

# Wait until all ebpf-mon LSM programs are detached
wait_for_bpf_cleanup() {
    for _ in $(seq 1 5); do
        local count
        count=$(bpftool prog list 2>/dev/null | grep -c "lsm.*enforce" || true)
        if [ "$count" -eq 0 ]; then
            return 0
        fi
        sleep 1
    done
    warn "Orphaned LSM programs detected — force-killing all ebpf-mon"
    kill_all_ebpf_mon
    sleep 2
}

# Kill ALL ebpf-mon processes (safety net)
kill_all_ebpf_mon() {
    local pids
    pids=$(pgrep -f "ebpf-mon" 2>/dev/null | grep -v "$$" || true)
    if [ -n "$pids" ]; then
        for p in $pids; do
            kill -INT "$p" 2>/dev/null || true
        done
        sleep 2
        for p in $pids; do
            kill -KILL "$p" 2>/dev/null || true
        done
    fi
}

# Trap to ensure cleanup on any exit
cleanup_on_exit() {
    if [ -n "$EBPF_PID" ] && kill -0 "$EBPF_PID" 2>/dev/null; then
        info "Cleaning up ebpf-mon (PID $EBPF_PID)..."
        stop_ebpf "$EBPF_PID"
    fi
    kill_all_ebpf_mon
}
trap cleanup_on_exit EXIT

# ─────────────────────────────────────────────────────────────
# Root check
# ─────────────────────────────────────────────────────────────

if [ "$(id -u)" -ne 0 ]; then
    fail "This script must be run as root (sudo ./demo.sh)"
fi

# ─────────────────────────────────────────────────────────────
# Prerequisite checks
# ─────────────────────────────────────────────────────────────

banner "PREREQUISITE CHECKS"

if ! command -v docker &>/dev/null; then
    fail "Docker is not installed"
fi
if ! docker info &>/dev/null; then
    fail "Docker daemon is not running"
fi
ok "Docker is available"

if [ -f /sys/kernel/security/lsm ]; then
    LSM_LIST=$(cat /sys/kernel/security/lsm)
    if echo "$LSM_LIST" | grep -q "bpf"; then
        ok "BPF-LSM is enabled ($LSM_LIST)"
    else
        fail "BPF-LSM is NOT enabled. Current LSMs: $LSM_LIST
    Add 'lsm=...,bpf' to your kernel boot parameters."
    fi
else
    warn "Cannot read /sys/kernel/security/lsm — BPF-LSM status unknown"
fi

if [ -f /sys/kernel/btf/vmlinux ]; then
    ok "BTF is available"
else
    fail "BTF not available at /sys/kernel/btf/vmlinux"
fi

# Clean up any stale ebpf-mon processes from previous runs
STALE=$(pgrep -f "ebpf-mon" 2>/dev/null | grep -v "$$" || true)
if [ -n "$STALE" ]; then
    warn "Found stale ebpf-mon processes: $STALE — killing them"
    kill_all_ebpf_mon
    sleep 1
fi
ok "No stale enforcement programs"

# ─────────────────────────────────────────────────────────────
# Build
# ─────────────────────────────────────────────────────────────

banner "CHECKING BINARY"

if [ ! -x "$EBPF_BIN" ]; then
    fail "Binary not found at $EBPF_BIN. Build first with:
    cd ebpf-mon-ebpf && cargo build --release && cd ../ebpf-mon && cargo build --release"
fi
ok "Binary ready: $EBPF_BIN"

# ─────────────────────────────────────────────────────────────
# PHASE 1: Profile
# ─────────────────────────────────────────────────────────────

if [ "$START_PHASE" -le 1 ]; then
    banner "PHASE 1: PROFILING"

    cleanup_container
    rm -f "$PROFILE_PATH"

    info "Starting test container: $CONTAINER_NAME ($CONTAINER_IMAGE)"
    docker run -d --name "$CONTAINER_NAME" "$CONTAINER_IMAGE" >/dev/null
    ok "Container started"

    info "Waiting for container to settle..."
    sleep 2

    info "Profiling container for ${PROFILE_DURATION} seconds..."
    echo ""

    cd "$SCRIPT_DIR/ebpf-mon"
    RUST_LOG=info "$EBPF_BIN" --name "$CONTAINER_NAME" > /tmp/demo-profile.log 2>&1 &
    EBPF_PID=$!
    cd "$SCRIPT_DIR"

    info "Waiting for monitor to attach (PID: $EBPF_PID)..."
    sleep 6

    info "Generating profiling workload..."
    for i in $(seq 1 3); do
        docker exec "$CONTAINER_NAME" sh -c "
            cat /etc/hostname >/dev/null 2>&1
            ls /etc/nginx/ >/dev/null 2>&1
            cat /proc/1/status >/dev/null 2>&1
            cat /etc/resolv.conf >/dev/null 2>&1
            ls /var/log/nginx/ >/dev/null 2>&1
        " >/dev/null 2>&1
        docker exec "$CONTAINER_NAME" wget -q -O /dev/null http://localhost/ 2>/dev/null || true
        sleep 2
    done

    ELAPSED=12
    REMAINING=$((PROFILE_DURATION - ELAPSED))
    if [ "$REMAINING" -gt 0 ]; then
        sleep "$REMAINING"
    fi

    info "Stopping profiler..."
    stop_ebpf "$EBPF_PID"
    EBPF_PID=""
    echo ""

    if [ -f "$PROFILE_PATH" ]; then
        RULE_COUNT=$(python3 -c "
import json
with open('$PROFILE_PATH') as f:
    data = json.load(f)
total = 0
for cat in ['fs', 'network', 'process']:
    if cat in data:
        total += len(data[cat])
print(total)
" 2>/dev/null || echo "?")
        ok "Profile saved to: $PROFILE_PATH"
        ok "Events captured: $RULE_COUNT"
    else
        fail "Profile was not created at $PROFILE_PATH"
    fi

    echo ""
    info "Profile summary:"
    python3 -c "
import json
with open('$PROFILE_PATH') as f:
    data = json.load(f)
for cat in ['fs', 'network', 'process']:
    if cat in data:
        print(f'  {cat}: {len(data[cat])} events')
    else:
        print(f'  {cat}: 0 events')
" 2>/dev/null || warn "Could not parse profile (python3 not available)"

    pause
fi

# ─────────────────────────────────────────────────────────────
# PHASE 2: Enforce (audit-only)
# ─────────────────────────────────────────────────────────────

if [ "$START_PHASE" -le 2 ]; then
    banner "PHASE 2: ENFORCEMENT (AUDIT-ONLY)"

    # Ensure no stale programs from Phase 1
    kill_all_ebpf_mon
    wait_for_bpf_cleanup

    if [ ! -f "$PROFILE_PATH" ]; then
        fail "No profile found at $PROFILE_PATH. Run Phase 1 first."
    fi

    info "Mode: AUDIT-ONLY (violations are logged but not blocked)"
    echo ""

    if ! docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
        info "Restarting container: $CONTAINER_NAME"
        cleanup_container
        docker run -d --name "$CONTAINER_NAME" "$CONTAINER_IMAGE" >/dev/null
        sleep 2
    fi

    cd "$SCRIPT_DIR/ebpf-mon"
    RUST_LOG=warn "$EBPF_BIN" --name "$CONTAINER_NAME" --enforce "$PROFILE_PATH" --audit-only > /tmp/demo-audit.log 2>&1 &
    EBPF_PID=$!
    cd "$SCRIPT_DIR"

    info "Waiting for enforcement to attach (PID: $EBPF_PID)..."
    sleep 8

    info "Testing AUTHORIZED operations (should succeed in audit-only)..."
    echo ""

    echo -n "  Reading /etc/hostname: "
    if docker exec "$CONTAINER_NAME" cat /etc/hostname >/dev/null 2>&1; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${RED}BLOCKED${NC} (unexpected in audit-only)"
    fi

    echo -n "  Listing /etc/nginx/: "
    if docker exec "$CONTAINER_NAME" ls /etc/nginx/ >/dev/null 2>&1; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${RED}BLOCKED${NC} (unexpected in audit-only)"
    fi

    echo ""
    info "Testing UNAUTHORIZED operations (should be logged but not blocked)..."
    echo ""

    echo -n "  Reading /etc/shadow: "
    if docker exec "$CONTAINER_NAME" cat /etc/shadow >/dev/null 2>&1; then
        echo -e "${YELLOW}ALLOWED (audit logged)${NC}"
    else
        echo -e "${RED}BLOCKED${NC} (unexpected in audit-only)"
    fi

    echo -n "  Writing to /tmp/evil.txt: "
    if docker exec "$CONTAINER_NAME" sh -c "echo pwned > /tmp/evil.txt" 2>/dev/null; then
        echo -e "${YELLOW}ALLOWED (audit logged)${NC}"
    else
        echo -e "${RED}BLOCKED${NC} (unexpected in audit-only)"
    fi

    echo ""
    info "Stopping audit-only enforcement..."
    stop_ebpf "$EBPF_PID"
    EBPF_PID=""

    pause
fi

# ─────────────────────────────────────────────────────────────
# PHASE 3: Enforce (active)
# ─────────────────────────────────────────────────────────────

if [ "$START_PHASE" -le 3 ]; then
    banner "PHASE 3: ENFORCEMENT (ACTIVE)"

    # Ensure no stale enforcement from Phase 2
    kill_all_ebpf_mon
    wait_for_bpf_cleanup

    if [ ! -f "$PROFILE_PATH" ]; then
        fail "No profile found at $PROFILE_PATH. Run Phase 1 first."
    fi

    echo -e "${RED}${BOLD}  WARNING: Active enforcement will BLOCK unauthorized operations${NC}"
    echo -e "${RED}${BOLD}  inside the container. This is scoped to the container's cgroup${NC}"
    echo -e "${RED}${BOLD}  and will NOT affect the host or other containers.${NC}"
    echo ""

    if ! docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
        info "Restarting container: $CONTAINER_NAME"
        cleanup_container
        docker run -d --name "$CONTAINER_NAME" "$CONTAINER_IMAGE" >/dev/null
        sleep 2
    fi

    info "Mode: ENFORCING (unauthorized operations will be BLOCKED)"
    echo ""

    cd "$SCRIPT_DIR/ebpf-mon"
    RUST_LOG=warn "$EBPF_BIN" --name "$CONTAINER_NAME" --enforce "$PROFILE_PATH" > /tmp/demo-enforce.log 2>&1 &
    EBPF_PID=$!
    cd "$SCRIPT_DIR"

    info "Waiting for enforcement to attach (PID: $EBPF_PID)..."
    sleep 8

    info "Testing AUTHORIZED operations (should succeed)..."
    echo ""

    echo -n "  Reading /etc/hostname: "
    if docker exec "$CONTAINER_NAME" cat /etc/hostname >/dev/null 2>&1; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${RED}BLOCKED (false positive — file not in profile)${NC}"
    fi

    echo -n "  Listing /etc/nginx/: "
    if docker exec "$CONTAINER_NAME" ls /etc/nginx/ >/dev/null 2>&1; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${RED}BLOCKED (false positive — file not in profile)${NC}"
    fi

    echo ""
    info "Testing UNAUTHORIZED operations (should be BLOCKED)..."
    echo ""

    echo -n "  Reading /etc/shadow: "
    if docker exec "$CONTAINER_NAME" cat /etc/shadow >/dev/null 2>&1; then
        echo -e "${YELLOW}ALLOWED (enforcement miss)${NC}"
    else
        echo -e "${GREEN}BLOCKED by LSM${NC}"
    fi

    echo -n "  Writing to /tmp/evil.txt: "
    if docker exec "$CONTAINER_NAME" sh -c "echo pwned > /tmp/evil.txt" 2>/dev/null; then
        echo -e "${YELLOW}ALLOWED (enforcement miss)${NC}"
    else
        echo -e "${GREEN}BLOCKED by LSM${NC}"
    fi

    echo -n "  Reading /etc/group: "
    if docker exec "$CONTAINER_NAME" cat /etc/group >/dev/null 2>&1; then
        echo -e "${YELLOW}ALLOWED (enforcement miss)${NC}"
    else
        echo -e "${GREEN}BLOCKED by LSM${NC}"
    fi

    echo -n "  Listing /root/: "
    if docker exec "$CONTAINER_NAME" ls /root/ >/dev/null 2>&1; then
        echo -e "${YELLOW}ALLOWED (enforcement miss)${NC}"
    else
        echo -e "${GREEN}BLOCKED by LSM${NC}"
    fi

    echo ""
    info "Stopping enforcement..."
    stop_ebpf "$EBPF_PID"
    EBPF_PID=""
fi

# ─────────────────────────────────────────────────────────────
# Cleanup
# ─────────────────────────────────────────────────────────────

banner "CLEANUP"

info "Stopping and removing test container..."
cleanup_container
ok "Container removed"

# Final safety: make sure no BPF programs are orphaned
sleep 1
REMAINING_LSM=$(bpftool prog list 2>/dev/null | grep -c "lsm.*enforce" || true)
if [ "$REMAINING_LSM" -gt 0 ]; then
    warn "Found $REMAINING_LSM orphaned LSM programs. Killing remaining ebpf-mon processes..."
    kill_all_ebpf_mon
    sleep 2
fi

echo ""
echo -e "${BOLD}Demo complete.${NC}"
echo ""
