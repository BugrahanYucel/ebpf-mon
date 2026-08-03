# eBPF Monitoring Tool - Test Harness

This test harness validates the completeness and accuracy of your eBPF monitoring tool by generating controlled workloads with known ground truth and comparing them against captured events.

## Overview

The test harness consists of three main components:

1. **`test_workload.py`** - Generates controlled operations and tracks ground truth
2. **`compare_results.py`** - Compares ground truth with eBPF captured events
3. **`run_validation.sh`** - Automated workflow script

## How It Works

### Event Tracking

The test harness tracks events using the same identity keys as your eBPF tool:

- **Network Events**: `(dst_ip, dst_port, direction)`
  - Captures both outgoing and incoming connections
  - Tracks frequency of operations to same destination
  
- **Filesystem Events**: `(inode, r_w, owner_uid)`
  - Tracks reads and writes separately
  - Uses inode to identify files (handles renames/moves)
  
- **Process Events**: `(inode, ps_type, cgroup)`
  - Tracks execve and fork separately
  - Note: PID is NOT part of identity (as per eBPF implementation)

### Frequency Tracking

The harness correctly models eBPF deduplication:
- Multiple operations with the same identity increment frequency
- Each unique identity appears once in output with its frequency count

## Usage

### Method 1: Automated Validation (Recommended for Development)

```bash
# 1. Make scripts executable
chmod +x run_validation.sh

# 2. Run automated validation
./run_validation.sh [output_dir]

# 3. Follow the prompts to run eBPF tool and workload
```

### Method 2: Manual Step-by-Step (Recommended for Testing)

This method gives you more control and is better for Docker testing:

#### Step 1: Start eBPF Tool

```bash
# Terminal 1: Run your eBPF monitoring tool
cd /home/bugrahanyucel/infrasec/projects/ebpf-mon
sudo ./target/release/ebpf-mon --cgroup <cgroup_path>

# For Docker testing, get the cgroup path:
docker inspect <container_id> | grep -i cgroup
```

#### Step 2: Run Test Workload and Generate Ground Truth

```bash
# Terminal 2: Run test workload
cd /home/bugrahanyucel/infrasec/projects/ebpf-mon/test-harness

# Option A: Run directly on host
python3 test_workload.py ground_truth.json

# Option B: Run in Docker container (RECOMMENDED)
docker run --rm -v $(pwd):/output python:3.9 \
  python3 /output/test_workload.py /output/ground_truth.json
```

#### Step 3: Let eBPF Tool Export Events

Wait for your eBPF tool to export events to `events.json` (or `final-events.json`). Check your tool's output for export location.

```bash
# Your tool exports to: ../ebpf-mon/events.json
# or ../ebpf-mon/final-events.json
```

#### Step 4: Compare Results

```bash
# Compare ground truth with eBPF captured events
python3 compare_results.py \
  ground_truth.json \
  ../ebpf-mon/events.json

# Output will show:
# - Matched events (captured correctly)
# - Missed events (in ground truth but not captured)
# - Extra events (captured but not in ground truth - usually background activity)
# - Accuracy percentage per category
```

## Docker Testing (Recommended)

For more realistic testing with container isolation:

```bash
# 1. Start eBPF tool targeting Docker cgroup
sudo ./target/release/ebpf-mon --cgroup /sys/fs/cgroup/docker/<container_id>

# 2. Run test workload in container
docker run --rm --name ebpf_test \
  -v $(pwd)/test-harness:/workload \
  python:3.9 \
  python3 /workload/test_workload.py /workload/ground_truth.json

# 3. Compare results
cd test-harness
python3 compare_results.py ground_truth.json ../ebpf-mon/events.json
```

## Interpreting Results

### Accuracy Metrics

- **95%+**: Excellent - Tool captures nearly all ground truth events
- **80-95%**: Good - Minor misses, acceptable for most use cases
- **60-80%**: Fair - Review configuration and filtering
- **<60%**: Needs improvement - Check eBPF program logic

### Understanding Output

#### ✓ Matched Events
Events that appear in both ground truth and eBPF output with matching identities. Frequency mismatches are highlighted.

#### ✗ Missed Events
Events in ground truth but NOT captured by eBPF tool. These indicate potential issues:
- Event filtering too aggressive
- Lost events (check eBPF perf buffer warnings)
- Timing issues (workload ran before eBPF attached)

#### ⚠ Extra Events
Events captured by eBPF but not in ground truth. This is **NORMAL** because:
- System background processes
- Library initialization code
- Python interpreter operations

**Key Point**: Focus on ensuring ground truth events are NOT missed, not on eliminating extra events.

## Customizing Tests

### Adding Custom Workloads

Edit `test_workload.py` and add your own test methods:

```python
def custom_network_test(self):
    """Your custom network test"""
    # Perform operation
    sock = socket.create_connection(('example.com', 443))
    
    # Track in ground truth
    self.tracker.track_network_event('example.com', 443, 'outgoing')
    
    sock.close()

# Add to main()
workload.custom_network_test()
```

### Testing Specific Scenarios

```python
# High-frequency operations (test deduplication)
for i in range(1000):
    with open('/tmp/test.txt', 'r') as f:
        f.read()
    tracker.track_fs_event('/tmp/test.txt', 'read')
# Should result in freq=1000 for single event

# Different ports to same IP (should be separate events)
for port in [80, 443, 8080]:
    sock = socket.create_connection(('1.1.1.1', port))
    tracker.track_network_event('1.1.1.1', port, 'outgoing')
    sock.close()
# Should result in 3 separate network events
```

## Troubleshooting

### Ground Truth Not Generated
- Check Python version (requires 3.6+)
- Check file permissions in output directory
- Run with `python3 -v test_workload.py` for verbose output

### eBPF Tool Not Capturing Events
- Ensure eBPF tool is running with sudo
- Check cgroup path is correct
- Verify workload runs AFTER eBPF tool attaches
- Check for "Lost events" warnings in eBPF output

### Frequency Mismatches
- eBPF deduplication happens at kernel level
- System may generate additional calls (libc, etc.)
- Expected behavior: `ebpf_freq >= ground_truth_freq`

### Too Many Extra Events
- Normal for host testing (system background activity)
- Use Docker containers for cleaner testing
- Filter by cgroup to isolate workload

## Advanced Usage

### Continuous Testing

```bash
#!/bin/bash
# Run validation in a loop
for i in {1..10}; do
    echo "=== Test Run $i ==="
    python3 test_workload.py "ground_truth_$i.json"
    # Wait for eBPF export
    sleep 10
    cp ../ebpf-mon/events.json "ebpf_output_$i.json"
    python3 compare_results.py "ground_truth_$i.json" "ebpf_output_$i.json"
done
```

### Performance Testing

```python
# Modify test_workload.py for high load
# Network stress test
for i in range(10000):
    try:
        sock = socket.create_connection(('1.1.1.1', 443))
        tracker.track_network_event('1.1.1.1', 443, 'outgoing')
        sock.close()
    except:
        pass

# Check if eBPF tool reports lost events
```

## Output Format

Both ground truth and eBPF output use identical JSON structure:

```json
{
  "cgroup": "686846",
  "network": [
    {
      "dst_ip": "1.1.1.1",
      "dst_port": 443,
      "direction": "outgoing",
      "freq": 5
    }
  ],
  "fs": [
    {
      "path": "/tmp/test.txt",
      "inode": 12345,
      "owner_uid": 1000,
      "r_w": "read",
      "freq": 10
    }
  ],
  "process": [
    {
      "exec_path": "/bin/echo",
      "inode": 67890,
      "ps_type": "execve",
      "pid": 12345,
      "cgroup": 686846,
      "freq": 3
    }
  ]
}
```

## Next Steps

1. **Run basic validation** to establish baseline accuracy
2. **Add domain-specific tests** matching your use case
3. **Integrate into CI/CD** for regression testing
4. **Create benchmark suite** with different workload patterns
5. **Test edge cases** (high frequency, network failures, etc.)

## Contributing

When adding new event types to your eBPF tool:
1. Update identity key in `test_workload.py`
2. Update comparison logic in `compare_results.py`
3. Add test scenarios in `test_workload.py`
4. Document expected behavior

## Support

For issues or questions:
- Check eBPF tool logs for warnings
- Verify ground truth is generated correctly
- Compare event identities manually
- Test with minimal workload first







