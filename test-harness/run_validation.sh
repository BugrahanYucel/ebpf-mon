#!/bin/bash
#
# Automated validation workflow for eBPF monitoring tool
# Usage: ./run_validation.sh [output_dir]
#

set -e

# Configuration
OUTPUT_DIR="${1:-./validation_results}"
GROUND_TRUTH="${OUTPUT_DIR}/ground_truth.json"
EBPF_OUTPUT="${OUTPUT_DIR}/ebpf_events.json"
EBPF_BINARY="../target/release/ebpf-mon"
EBPF_CGROUP_PATH="/sys/fs/cgroup/docker"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Create output directory
mkdir -p "$OUTPUT_DIR"

echo "============================================================"
echo "  eBPF Monitoring Tool - Automated Validation"
echo "============================================================"
echo "Output directory: $OUTPUT_DIR"
echo ""

# Step 1: Generate ground truth
print_step "Step 1: Generating ground truth by running test workload..."
python3 test_workload.py "$GROUND_TRUTH"

if [ ! -f "$GROUND_TRUTH" ]; then
    print_error "Failed to generate ground truth"
    exit 1
fi

print_success "Ground truth generated: $GROUND_TRUTH"
echo ""

# Step 2: Run eBPF tool
print_step "Step 2: Running eBPF monitoring tool..."

# Check if eBPF binary exists
if [ ! -f "$EBPF_BINARY" ]; then
    print_warning "eBPF binary not found at $EBPF_BINARY"
    print_step "Building eBPF tool..."
    (cd .. && cargo build --release)
fi

print_warning "You need to run the eBPF tool manually with proper permissions"
print_warning "In a separate terminal, run:"
echo ""
echo "  sudo $EBPF_BINARY --cgroup <cgroup_path>"
echo ""
print_warning "Then run the test workload again:"
echo ""
echo "  python3 test_workload.py /tmp/test_ground_truth.json"
echo ""
print_warning "Wait for the eBPF tool to export events to events.json"
print_warning "Then copy the events.json to: $EBPF_OUTPUT"
echo ""
read -p "Press Enter when you have copied the eBPF output to $EBPF_OUTPUT..."

# Step 3: Compare results
print_step "Step 3: Comparing ground truth with eBPF output..."

if [ ! -f "$EBPF_OUTPUT" ]; then
    print_error "eBPF output not found at $EBPF_OUTPUT"
    exit 1
fi

python3 compare_results.py "$GROUND_TRUTH" "$EBPF_OUTPUT" | tee "${OUTPUT_DIR}/validation_report.txt"

print_success "Validation complete! Report saved to ${OUTPUT_DIR}/validation_report.txt"
echo ""
echo "============================================================"







