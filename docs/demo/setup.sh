#!/usr/bin/env bash
#
# DEMO SETUP — run ONCE before the talk (or after a reboot).
#
# What it does:
#   1. Preflight (docker, BPF-LSM, toolchain)
#   2. Prebuild ebpf bytecode + ebpf-mon binary + cross_format example
#   3. Build the three demo images (workload, vulnapp, secretsvc)
#   4. Run them with --restart unless-stopped; capture IDs into .demo-env
#   5. Pre-profile vulnapp + secretsvc (warmup traffic while monitoring)
#
# Usage:  sudo ./docs/demo/setup.sh [--skip-build] [--skip-profile] [--profile-secs N]
#
# After this succeeds:  ./docs/demo/run-demo.sh
set -euo pipefail

DEMO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$DEMO_DIR/lib.sh"

SKIP_BUILD=0
SKIP_PROFILE=0
PROFILE_SECS=20

while [[ $# -gt 0 ]]; do
    case "$1" in
        --skip-build)   SKIP_BUILD=1; shift ;;
        --skip-profile) SKIP_PROFILE=1; shift ;;
        --profile-secs) PROFILE_SECS="$2"; shift 2 ;;
        -h|--help)
            cat <<'EOF'
DEMO SETUP — run ONCE before the talk (or after a reboot).

  1. Preflight (docker, BPF-LSM, toolchain)
  2. Prebuild ebpf bytecode + ebpf-mon binary + cross_format example
  3. Build the three demo images (workload, vulnapp, secretsvc)
  4. Run them with --restart unless-stopped; capture IDs into .demo-env
  5. Pre-profile vulnapp + secretsvc (warmup traffic while monitoring)

Usage:  ./docs/demo/setup.sh [--skip-build] [--skip-profile] [--profile-secs N]

After this succeeds:  ./docs/demo/run-demo.sh
EOF
            exit 0
            ;;
        *) echo "unknown arg: $1"; exit 1 ;;
    esac
done

echo -e "${C}${BOLD}=== ebpf-mon demo setup ===${NC}"
echo -e "${D}repo: $REPO_ROOT${NC}"
echo

# ── 1. Preflight ────────────────────────────────────────────────────────────
echo -e "${B}[1/5] Preflight${NC}"

if ! command -v docker >/dev/null 2>&1; then
    echo -e "${R}error:${NC} docker not found"; exit 1
fi
if ! docker info >/dev/null 2>&1; then
    echo -e "${R}error:${NC} cannot talk to docker daemon (permission denied?)."
    echo -e "  Try: sudo usermod -aG docker \$USER && newgrp docker"
    echo -e "  Or run this script with a user that can run 'docker ps'."
    exit 1
fi
echo -e "  ${G}ok${NC} docker"

if [ ! -r /sys/kernel/security/lsm ] || ! grep -qw bpf /sys/kernel/security/lsm; then
    echo -e "  ${Y}warn${NC} BPF-LSM not in /sys/kernel/security/lsm"
    echo -e "       Enforcement chapters will fail. Add 'bpf' to the lsm= boot param and reboot."
else
    echo -e "  ${G}ok${NC} BPF-LSM active ($(cat /sys/kernel/security/lsm))"
fi
if [ ! -e /sys/kernel/btf/vmlinux ]; then
    echo -e "  ${Y}warn${NC} /sys/kernel/btf/vmlinux missing (BTF required for CO-RE / LSM)"
else
    echo -e "  ${G}ok${NC} BTF available"
fi

if [ "$SKIP_BUILD" = "0" ]; then
    if ! command -v cargo >/dev/null 2>&1; then
        echo -e "${R}error:${NC} cargo not found on PATH"; exit 1
    fi
    if ! command -v bpf-linker >/dev/null 2>&1; then
        echo -e "${Y}warn${NC} bpf-linker not on PATH — attempting cargo install..."
        cargo install bpf-linker || {
            echo -e "${R}error:${NC} bpf-linker install failed"; exit 1; }
    fi
    echo -e "  ${G}ok${NC} cargo + bpf-linker"
fi
echo

# ── 2. Prebuild ─────────────────────────────────────────────────────────────
if [ "$SKIP_BUILD" = "0" ]; then
    echo -e "${B}[2/5] Prebuild (so nothing compiles on stage)${NC}"
    echo -e "  ${D}eBPF bytecode...${NC}"
    (cd "$REPO_ROOT/ebpf-mon-ebpf" && cargo build --release) \
        || { echo -e "${R}error:${NC} ebpf-mon-ebpf build failed"; exit 1; }
    echo -e "  ${D}userspace binary...${NC}"
    (cd "$REPO_ROOT/ebpf-mon" && cargo build --release) \
        || { echo -e "${R}error:${NC} ebpf-mon build failed"; exit 1; }
    echo -e "  ${D}cross_format example (cap6)...${NC}"
    (cd "$REPO_ROOT" && cargo build -q -p ebpf-mon-common --features user --example cross_format) \
        || { echo -e "${R}error:${NC} cross_format build failed"; exit 1; }
    [ -x "$BIN" ] || { echo -e "${R}error:${NC} expected binary at $BIN"; exit 1; }
    echo -e "  ${G}ok${NC} $BIN"
else
    echo -e "${B}[2/5] Prebuild skipped (--skip-build)${NC}"
    [ -x "$BIN" ] || echo -e "  ${Y}warn${NC} $BIN not found — enforcement chapters will fail"
fi
echo

# ── 3. Build images ─────────────────────────────────────────────────────────
echo -e "${B}[3/5] Build demo images${NC}"
docker build -t ebpf-mon-workload:latest "$DEMO_DIR/workload"
docker build -t vulnapp:latest           "$DEMO_DIR/cve"
docker build -t secretsvc:latest         "$DEMO_DIR/secretsvc"
echo -e "  ${G}ok${NC} images built"
echo

# ── 4. Run containers (never go down) ───────────────────────────────────────
echo -e "${B}[4/5] Run containers (--restart unless-stopped)${NC}"

run_or_replace() {
    local name="$1"; shift
    # Use `docker container inspect` (not bare `inspect`) so an IMAGE with the
    # same name (e.g. vulnapp:latest) is not mistaken for a running container.
    if docker container inspect "$name" >/dev/null 2>&1; then
        local status
        status="$(docker container inspect -f '{{.State.Status}}' "$name")"
        if [ "$status" = "running" ]; then
            echo -e "  ${D}$name already running — leaving it${NC}"
            return 0
        fi
        echo -e "  ${Y}$name exists ($status) — removing and recreating${NC}"
        docker rm -f "$name" >/dev/null
    fi
    docker run -d --name "$name" --restart unless-stopped "$@" >/dev/null
    echo -e "  ${G}started${NC} $name"
}

run_or_replace "$WORKLOAD_NAME" \
    -e SLEEP_SECONDS=2 -e EXTERNAL_NET=1 \
    ebpf-mon-workload:latest

# SECURITY: bind published ports to loopback ONLY by default. vulnapp is an
# unauthenticated RCE and secretsvc leaks a secret; publishing on 0.0.0.0 would
# expose them to anyone on the same (often untrusted, e.g. conference) network.
# The demo only ever curls 127.0.0.1, so loopback is all we need. Override with
# BIND_ADDR=0.0.0.0 ONLY on an isolated/trusted host.
BIND_ADDR="${BIND_ADDR:-127.0.0.1}"
if [ "$BIND_ADDR" != "127.0.0.1" ] && [ "$BIND_ADDR" != "localhost" ]; then
    echo -e "  ${Y}warn${NC} BIND_ADDR=$BIND_ADDR — app ports will be reachable off-host (RCE/secret exposure)"
fi

run_or_replace "$VULNAPP_NAME" \
    -p "${BIND_ADDR}:${VULNAPP_PORT}:8080" \
    vulnapp:latest

run_or_replace "$SECRETSVC_NAME" \
    -p "${BIND_ADDR}:${SECRETSVC_PORT}:8081" \
    secretsvc:latest

# Quick smoke that HTTP endpoints answer
sleep 1
for url in "http://127.0.0.1:${VULNAPP_PORT}/" "http://127.0.0.1:${SECRETSVC_PORT}/"; do
    if curl -sf -m 3 "$url" >/dev/null; then
        echo -e "  ${G}ok${NC} $url"
    else
        echo -e "  ${Y}warn${NC} $url not answering yet (may need a second)"
    fi
done

write_demo_env
echo

# ── 5. Pre-profile vulnapp + secretsvc ──────────────────────────────────────
if [ "$SKIP_PROFILE" = "1" ]; then
    echo -e "${B}[5/5] Pre-profile skipped (--skip-profile)${NC}"
else
    echo -e "${B}[5/5] Pre-profile (warmup + monitor → events JSON)${NC}"
    # profile_one + count_events live in lib.sh (single source of truth).
    if [ "$(id -u)" -ne 0 ]; then
        echo -e "  ${Y}note${NC} profiling needs root; re-running the profile steps under sudo..."
        # Re-exec just the profile portion as root, keeping env.
        sudo env "PATH=$PATH" "HOME=$HOME" \
            DEMO_DIR="$DEMO_DIR" REPO_ROOT="$REPO_ROOT" BIN="$BIN" \
            VULNAPP_NAME="$VULNAPP_NAME" VULNAPP_PORT="$VULNAPP_PORT" \
            SECRETSVC_NAME="$SECRETSVC_NAME" SECRETSVC_PORT="$SECRETSVC_PORT" \
            PROFILE_SECS="$PROFILE_SECS" \
            bash -c '
                source "$DEMO_DIR/lib.sh"
                profile_one "$VULNAPP_NAME"   "$VULNAPP_PORT"   "$DEMO_DIR/vulnapp-events.json"   "$DEMO_DIR/cve/cve-demo.sh"   || true
                profile_one "$SECRETSVC_NAME" "$SECRETSVC_PORT" "$DEMO_DIR/secretsvc-events.json" "$DEMO_DIR/exfil-demo.sh"     || true
            '
    else
        profile_one "$VULNAPP_NAME"   "$VULNAPP_PORT"   "$DEMO_DIR/vulnapp-events.json"   "$DEMO_DIR/cve/cve-demo.sh"   || true
        profile_one "$SECRETSVC_NAME" "$SECRETSVC_PORT" "$DEMO_DIR/secretsvc-events.json" "$DEMO_DIR/exfil-demo.sh"     || true
    fi
    # Refresh .demo-env so EVENTS paths are current
    write_demo_env
fi
echo

# ── Summary ─────────────────────────────────────────────────────────────────
echo -e "${C}${BOLD}=== ready ===${NC}"
docker ps --filter "name=ebpf-mon-workload" --filter "name=vulnapp" --filter "name=secretsvc" \
    --format "table {{.Names}}\t{{.ID}}\t{{.Status}}\t{{.Ports}}"
echo
echo -e "  env file : ${G}$ENV_FILE${NC}"
echo -e "  next     : ${G}./docs/demo/run-demo.sh${NC}"
echo -e "  record   : ${G}./docs/demo/run-demo.sh --record${NC}"
echo -e "  skip to  : ${G}./docs/demo/run-demo.sh --from 7${NC}   # jump to RCE chapter"
echo
echo -e "${D}Standalone fallbacks still work: cap1..cap7, cve/cve-demo.sh, exfil-demo.sh${NC}"
