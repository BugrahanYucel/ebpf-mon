#!/bin/bash
#
# Automated Docker testing with proper sequencing
# Solves the chicken-and-egg problem of container ID vs eBPF attachment
#

set -e

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}======================================${NC}"
echo -e "${BLUE}eBPF Container Testing - Automated${NC}"
echo -e "${BLUE}======================================${NC}"
echo ""

# Configuration
CONTAINER_NAME="ebpf-test-$$"  # Unique name using PID
EBPF_DIR="${EBPF_DIR:-..}"  # Path to ebpf-mon root directory
OUTPUT_DIR="${1:-./validation_results}"

mkdir -p "$OUTPUT_DIR"

# Cleanup function
cleanup() {
    echo -e "\n${YELLOW}[CLEANUP]${NC} Stopping container..."
    docker rm -f "$CONTAINER_NAME" 2>/dev/null || true
    
    if [ ! -z "$EBPF_PID" ]; then
        echo -e "${YELLOW}[CLEANUP]${NC} Stopping eBPF tool..."
        sudo kill $EBPF_PID 2>/dev/null || true
    fi
}

trap cleanup EXIT

# Step 1: Start long-running container
echo -e "${GREEN}[STEP 1]${NC} Starting container in idle mode..."
docker run -d --name "$CONTAINER_NAME" \
    -v "$(pwd):/workload" \
    python:3.9 \
    sleep infinity

echo -e "${GREEN}[SUCCESS]${NC} Container started: $CONTAINER_NAME"

# Step 2: Get cgroup path
echo -e "\n${GREEN}[STEP 2]${NC} Getting container cgroup path..."
CONTAINER_ID=$(docker inspect "$CONTAINER_NAME" -f '{{.Id}}')

# Try different cgroup path formats (depends on system)
if [ -d "/sys/fs/cgroup/system.slice/docker-${CONTAINER_ID}.scope" ]; then
    CGROUP_PATH="/sys/fs/cgroup/system.slice/docker-${CONTAINER_ID}.scope"
elif [ -d "/sys/fs/cgroup/docker/${CONTAINER_ID}" ]; then
    CGROUP_PATH="/sys/fs/cgroup/docker/${CONTAINER_ID}"
else
    # Fallback: monitor all Docker containers
    CGROUP_PATH="/sys/fs/cgroup/system.slice/docker.service"
    echo -e "${YELLOW}[WARNING]${NC} Specific container cgroup not found"
    echo -e "${YELLOW}[WARNING]${NC} Monitoring entire Docker cgroup: $CGROUP_PATH"
fi

echo -e "${GREEN}[SUCCESS]${NC} Cgroup path: $CGROUP_PATH"

# Step 3: Start eBPF monitoring tool using unified script
echo -e "\n${GREEN}[STEP 3]${NC} Building and starting eBPF monitoring tool..."
echo -e "${BLUE}[INFO]${NC} Using: ${EBPF_DIR}/run-ebpf.sh --container $CONTAINER_NAME"

# Use the unified run script with container argument
"${EBPF_DIR}/run-ebpf.sh" --container "$CONTAINER_NAME" > "${OUTPUT_DIR}/ebpf_output.log" 2>&1 &
EBPF_PID=$!

# Wait for eBPF to attach
echo -e "${BLUE}[INFO]${NC} Waiting for eBPF to attach (5 seconds)..."
sleep 5

# Check if eBPF is still running
if ! ps -p $EBPF_PID > /dev/null; then
    echo -e "${YELLOW}[ERROR]${NC} eBPF tool failed to start!"
    echo -e "${YELLOW}[ERROR]${NC} Check log: ${OUTPUT_DIR}/ebpf_output.log"
    cat "${OUTPUT_DIR}/ebpf_output.log"
    exit 1
fi

echo -e "${GREEN}[SUCCESS]${NC} eBPF tool running (PID: $EBPF_PID)"

# Step 4: Run test workload inside the monitored container
echo -e "\n${GREEN}[STEP 4]${NC} Running test workload inside container..."
docker exec "$CONTAINER_NAME" \
    python3 /workload/test_workload.py /workload/ground_truth.json

echo -e "${GREEN}[SUCCESS]${NC} Test workload completed"

# Copy ground truth from container to host
if [ -f "ground_truth.json" ]; then
    mv ground_truth.json "${OUTPUT_DIR}/ground_truth.json"
    echo -e "${GREEN}[SUCCESS]${NC} Ground truth saved: ${OUTPUT_DIR}/ground_truth.json"
fi

# Step 5: Wait for eBPF to export events
echo -e "\n${GREEN}[STEP 5]${NC} Waiting for eBPF to export events..."
echo -e "${BLUE}[INFO]${NC} Waiting 30 seconds for event export..."
sleep 30

# Check if events.json was created
EVENTS_FILE="../ebpf-mon/events.json"
if [ ! -f "$EVENTS_FILE" ]; then
    EVENTS_FILE="../ebpf-mon/final-events.json"
fi

if [ ! -f "$EVENTS_FILE" ]; then
    echo -e "${YELLOW}[WARNING]${NC} Events file not found yet"
    echo -e "${BLUE}[INFO]${NC} Waiting additional 30 seconds..."
    sleep 30
fi

if [ -f "$EVENTS_FILE" ]; then
    cp "$EVENTS_FILE" "${OUTPUT_DIR}/ebpf_events.json"
    echo -e "${GREEN}[SUCCESS]${NC} eBPF events saved: ${OUTPUT_DIR}/ebpf_events.json"
else
    echo -e "${YELLOW}[ERROR]${NC} eBPF events file not found!"
    echo -e "${YELLOW}[ERROR]${NC} Expected at: $EVENTS_FILE"
    echo -e "${YELLOW}[INFO]${NC} Check eBPF output log:"
    tail -20 "${OUTPUT_DIR}/ebpf_output.log"
    exit 1
fi

# Step 6: Compare results
echo -e "\n${GREEN}[STEP 6]${NC} Comparing results..."
python3 compare_results.py \
    "${OUTPUT_DIR}/ground_truth.json" \
    "${OUTPUT_DIR}/ebpf_events.json" \
    | tee "${OUTPUT_DIR}/validation_report.txt"

echo -e "\n${GREEN}[COMPLETE]${NC} Validation complete!"
echo -e "${BLUE}[INFO]${NC} Results saved to: ${OUTPUT_DIR}/"
echo -e "${BLUE}[INFO]${NC} Files:"
echo -e "  - ${OUTPUT_DIR}/ground_truth.json"
echo -e "  - ${OUTPUT_DIR}/ebpf_events.json"
echo -e "  - ${OUTPUT_DIR}/validation_report.txt"
echo -e "  - ${OUTPUT_DIR}/ebpf_output.log"

