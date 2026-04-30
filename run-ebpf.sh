#!/bin/bash
#
# Unified script to build and run eBPF monitoring tool
# Usage: ./run-ebpf.sh [OPTIONS]
#
# Options:
#   --name <name>          Specify Docker container by name (with restart tracking)
#   --container <id>       Specify Docker container by ID (will try to enable restart tracking)
#   --cgroup <path>        Specify cgroup path directly (no restart tracking)
#   --help                 Show this help message
#
# Only one of --name, --container, or --cgroup can be specified.
# If none are provided, uses default cgroup (user.slice).
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Default values
CONTAINER_NAME=""
CONTAINER_ID=""
CGROUP_PATH=""
ENFORCE_PROFILE=""
AUDIT_ONLY=""
DEFAULT_CGROUP="/sys/fs/cgroup/user.slice"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --name)
            if [ -n "$CONTAINER_ID" ] || [ -n "$CGROUP_PATH" ]; then
                echo -e "${RED}[ERROR]${NC} --name, --container, and --cgroup are mutually exclusive"
                exit 1
            fi
            CONTAINER_NAME="$2"
            shift 2
            ;;
        --container)
            if [ -n "$CONTAINER_NAME" ] || [ -n "$CGROUP_PATH" ]; then
                echo -e "${RED}[ERROR]${NC} --name, --container, and --cgroup are mutually exclusive"
                exit 1
            fi
            CONTAINER_ID="$2"
            shift 2
            ;;
        --cgroup|--cg-file)
            if [ -n "$CONTAINER_NAME" ] || [ -n "$CONTAINER_ID" ]; then
                echo -e "${RED}[ERROR]${NC} --name, --container, and --cgroup are mutually exclusive"
                exit 1
            fi
            CGROUP_PATH="$2"
            shift 2
            ;;
        --enforce)
            ENFORCE_PROFILE="$2"
            shift 2
            ;;
        --audit-only)
            AUDIT_ONLY="--audit-only"
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Build and run eBPF monitoring tool with container restart tracking support."
            echo ""
            echo "Options:"
            echo "  --name <name>       Specify Docker container by name"
            echo "                      Enables restart tracking - events continue after container restarts"
            echo ""
            echo "  --container <id>    Specify Docker container by ID (full or short)"
            echo "                      Will resolve name automatically for restart tracking"
            echo ""
            echo "  --cgroup <path>     Specify cgroup path directly"
            echo "                      No restart tracking available"
            echo ""
            echo "  --enforce <file>    Load a profile JSON and enforce it via BPF-LSM"
            echo "                      (requires BPF-LSM kernel support)"
            echo ""
            echo "  --audit-only        With --enforce: log violations without blocking"
            echo ""
            echo "  --help              Show this help message"
            echo ""
            echo "Note: Only ONE of --name, --container, or --cgroup can be specified."
            echo ""
            echo "Examples:"
            echo ""
            echo "  # Monitor container by name (RECOMMENDED - full restart tracking)"
            echo -e "  ${CYAN}$0 --name nginx-prod${NC}"
            echo ""
            echo "  # Monitor container by ID (will try to enable restart tracking)"
            echo -e "  ${CYAN}$0 --container my-container${NC}"
            echo -e "  ${CYAN}$0 --container a1b2c3d4e5f6${NC}"
            echo ""
            echo "  # Monitor by cgroup path (no restart tracking)"
            echo -e "  ${CYAN}$0 --cgroup /sys/fs/cgroup/system.slice/docker-abc123.scope${NC}"
            echo ""
            echo "  # Monitor all Docker containers"
            echo -e "  ${CYAN}$0 --cgroup /sys/fs/cgroup/system.slice/docker.service${NC}"
            echo ""
            echo "  # Use default cgroup (user.slice)"
            echo -e "  ${CYAN}$0${NC}"
            echo ""
            echo "Restart Tracking:"
            echo "  When using --name or --container (with resolvable name), the profiler"
            echo "  will automatically detect container restarts and update the eBPF filter"
            echo "  to continue capturing events from the new container instance."
            exit 0
            ;;
        *)
            echo -e "${RED}[ERROR]${NC} Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Determine run mode and validate
RUN_MODE=""
RUN_ARG=""

if [ -n "$CONTAINER_NAME" ]; then
    RUN_MODE="name"
    RUN_ARG="$CONTAINER_NAME"
    echo -e "${BLUE}[INFO]${NC} Mode: Container by name (restart tracking enabled)"
    echo -e "${BLUE}[INFO]${NC} Container name: ${GREEN}$CONTAINER_NAME${NC}"
    
    # Validate container exists
    echo -e "${BLUE}[INFO]${NC} Validating container exists..."
    if ! docker inspect "$CONTAINER_NAME" -f '{{.Name}}' >/dev/null 2>&1; then
        echo -e "${RED}[ERROR]${NC} Container not found: $CONTAINER_NAME"
        echo ""
        echo "Available containers:"
        docker ps -a --format "table {{.Names}}\t{{.ID}}\t{{.Status}}" 2>/dev/null || \
            echo "(Cannot access Docker - try with sudo)"
        exit 1
    fi
    echo -e "${GREEN}[SUCCESS]${NC} Container '$CONTAINER_NAME' found"
    
elif [ -n "$CONTAINER_ID" ]; then
    RUN_MODE="container"
    RUN_ARG="$CONTAINER_ID"
    echo -e "${BLUE}[INFO]${NC} Mode: Container by ID (will try to enable restart tracking)"
    echo -e "${BLUE}[INFO]${NC} Container ID: ${GREEN}$CONTAINER_ID${NC}"
    
    # Validate container exists and get full ID
    echo -e "${BLUE}[INFO]${NC} Validating container exists..."
    DOCKER_OUTPUT=$(docker inspect "$CONTAINER_ID" -f '{{.Id}}' 2>&1)
    DOCKER_EXIT=$?
    
    if [ $DOCKER_EXIT -ne 0 ]; then
        if echo "$DOCKER_OUTPUT" | grep -q "permission denied"; then
            echo -e "${RED}[ERROR]${NC} Docker permission denied"
            echo -e "${YELLOW}[FIX]${NC} Run one of these:"
            echo "  1. Add user to docker group: sudo usermod -aG docker \$USER && newgrp docker"
            echo "  2. Run with sudo: sudo $0 --container $CONTAINER_ID"
            exit 1
        fi
        echo -e "${RED}[ERROR]${NC} Container not found: $CONTAINER_ID"
        echo ""
        echo "Available containers:"
        docker ps -a --format "table {{.ID}}\t{{.Names}}\t{{.Status}}" 2>/dev/null || \
            echo "(Cannot access Docker - try with sudo)"
        exit 1
    fi
    
    FULL_CONTAINER_ID="$DOCKER_OUTPUT"
    CONTAINER_NAME_RESOLVED=$(docker inspect "$CONTAINER_ID" -f '{{.Name}}' 2>/dev/null | sed 's|^/||')
    
    echo -e "${GREEN}[SUCCESS]${NC} Container found: ${FULL_CONTAINER_ID:0:12}..."
    if [ -n "$CONTAINER_NAME_RESOLVED" ]; then
        echo -e "${GREEN}[SUCCESS]${NC} Resolved name: $CONTAINER_NAME_RESOLVED (restart tracking will be enabled)"
    else
        echo -e "${YELLOW}[WARNING]${NC} Could not resolve container name (restart tracking may be disabled)"
    fi
    
elif [ -n "$CGROUP_PATH" ]; then
    RUN_MODE="cgroup"
    RUN_ARG="$CGROUP_PATH"
    echo -e "${BLUE}[INFO]${NC} Mode: Direct cgroup path (no restart tracking)"
    echo -e "${BLUE}[INFO]${NC} Cgroup path: ${GREEN}$CGROUP_PATH${NC}"
    
    # Verify cgroup path exists
    if [ ! -d "$CGROUP_PATH" ]; then
        echo -e "${RED}[ERROR]${NC} Cgroup path does not exist: $CGROUP_PATH"
        echo ""
        echo "Available cgroups in system.slice:"
        ls -1 /sys/fs/cgroup/system.slice/ 2>/dev/null | head -20 || echo "(none found)"
        exit 1
    fi
    echo -e "${GREEN}[SUCCESS]${NC} Cgroup path exists"
    
else
    # No arguments - use default cgroup
    RUN_MODE="cgroup"
    RUN_ARG="$DEFAULT_CGROUP"
    echo -e "${BLUE}[INFO]${NC} Mode: Default cgroup (no container specified)"
    echo -e "${BLUE}[INFO]${NC} Using default: ${GREEN}$DEFAULT_CGROUP${NC}"
    
    if [ ! -d "$DEFAULT_CGROUP" ]; then
        echo -e "${RED}[ERROR]${NC} Default cgroup path does not exist: $DEFAULT_CGROUP"
        exit 1
    fi
fi

echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  eBPF Monitoring Tool - Build & Run${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}Mode:${NC}     --$RUN_MODE"
echo -e "${BLUE}Target:${NC}   $RUN_ARG"
if [ "$RUN_MODE" = "name" ] || [ "$RUN_MODE" = "container" ]; then
    echo -e "${BLUE}Restart:${NC}  ${GREEN}Tracking Enabled${NC}"
else
    echo -e "${BLUE}Restart:${NC}  ${YELLOW}Tracking Disabled${NC}"
fi
echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
echo ""

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Step 1: Build eBPF bytecode
echo -e "${BLUE}[STEP 1/2]${NC} Building eBPF bytecode..."
cd "$SCRIPT_DIR/ebpf-mon-ebpf"

if cargo build --release 2>&1 | tail -5; then
    echo -e "${GREEN}[SUCCESS]${NC} eBPF bytecode built successfully"
else
    echo -e "${RED}[ERROR]${NC} Failed to build eBPF bytecode"
    exit 1
fi

echo ""

# Step 2: Run eBPF monitoring tool
echo -e "${BLUE}[STEP 2/2]${NC} Starting eBPF monitoring tool..."
cd "$SCRIPT_DIR/ebpf-mon"

echo -e "${BLUE}[INFO]${NC} Running: cargo run --release -- --$RUN_MODE \"$RUN_ARG\""
echo -e "${YELLOW}[NOTE]${NC} Press Ctrl+C to stop monitoring"
echo ""

# Build enforcement flags
ENFORCE_FLAGS=""
if [ -n "$ENFORCE_PROFILE" ]; then
    ENFORCE_FLAGS="--enforce $ENFORCE_PROFILE $AUDIT_ONLY"
    echo -e "${BLUE}[INFO]${NC} Enforcement profile: ${GREEN}$ENFORCE_PROFILE${NC}"
    if [ -n "$AUDIT_ONLY" ]; then
        echo -e "${YELLOW}[INFO]${NC} Mode: AUDIT-ONLY (violations logged, not blocked)"
    else
        echo -e "${RED}[INFO]${NC} Mode: ENFORCING (unauthorized access will be blocked)"
    fi
fi

# Run with proper cargo command
RUST_LOG=info cargo run --release \
    --config 'target."cfg(all())".runner="sudo -E"' \
    -- --$RUN_MODE "$RUN_ARG" $ENFORCE_FLAGS
