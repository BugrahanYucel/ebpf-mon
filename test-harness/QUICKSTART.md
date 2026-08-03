# Quick Start Guide

## TL;DR - Fast Testing

### Option 1: Use Unified Script (Easiest) ⭐
```bash
# Terminal 1: Start eBPF tool (builds automatically)
cd /home/bugrahanyucel/infrasec/projects/ebpf-mon
./run-ebpf.sh

# Terminal 2: Run test workload
cd test-harness
python3 test_workload.py ground_truth.json

# Wait 10-30 seconds for eBPF to export events.json

# Terminal 2: Compare results
python3 compare_results.py ground_truth.json ../ebpf-mon/events.json
```

### Option 2: Fully Automated (Zero Manual Steps) 🚀
```bash
# One command does everything!
cd test-harness
./docker_test.sh ./validation_results
```

## What to Look For

### ✅ Good Results
```
Overall Accuracy: >90%
Matched: Most ground truth events appear in eBPF output
Extra Events: Many (this is normal - system background activity)
```

### ❌ Problems
```
Missed Events: Ground truth events NOT in eBPF output
Lost Events: eBPF warns about lost events (increase buffer)
Frequency Mismatches: eBPF freq < ground truth freq
```

## Docker Testing (Recommended)

### 🎯 Automated (One Command)

**Solves the chicken-and-egg problem automatically!**

```bash
# Automated Docker testing - handles sequencing for you
cd test-harness
./docker_test.sh ./validation_results

# That's it! Script handles:
# 1. Starting container in idle mode
# 2. Getting cgroup path
# 3. Starting eBPF tool
# 4. Running workload inside monitored container
# 5. Comparing results
```

### Manual Method (For Learning)

**Problem**: You need container ID before starting eBPF, but container doesn't exist yet!

**Solution**: Start container in idle mode, THEN run workload:

```bash
# Terminal 1: Start container WITHOUT running workload yet
docker run -d --name test-container \
  -v $(pwd):/workload \
  python:3.9 sleep infinity

# Start eBPF monitoring (builds automatically, auto-detects cgroup)
cd ..
./run-ebpf.sh --container test-container

# Terminal 2: NOW run workload inside already-monitored container
cd test-harness
docker exec test-container \
  python3 /workload/test_workload.py /workload/ground_truth.json

# Copy ground truth
docker cp test-container:/workload/ground_truth.json .

# Wait for export, then compare
python3 compare_results.py ground_truth.json ../ebpf-mon/events.json

# Cleanup
docker rm -f test-container
```

**Even simpler with cgroup path:**
```bash
# Just pass custom cgroup directly
./run-ebpf.sh --cg-file /sys/fs/cgroup/system.slice/docker.service
```

## Understanding Output

### Network Events
```json
{
  "dst_ip": "1.1.1.1",      # Destination IP
  "dst_port": 443,           # Destination port
  "direction": "outgoing",   # outgoing=1, incoming=0
  "freq": 5                  # Number of operations
}
```

**Identity**: `(dst_ip, dst_port, direction)`
- Multiple connections to same dest increment freq
- Different ports = different events

### Filesystem Events
```json
{
  "path": "/tmp/test.txt",
  "inode": 12345,            # File identifier
  "owner_uid": 1000,         # File owner
  "r_w": "read",             # read=0, write=1
  "freq": 10
}
```

**Identity**: `(inode, r_w, owner_uid)`
- Read and write to same file = 2 events
- Multiple reads of same file increment freq

### Process Events
```json
{
  "exec_path": "/bin/echo",
  "inode": 67890,            # Executable inode
  "ps_type": "execve",       # execve=0, fork=1
  "pid": 12345,              # Process ID (not in identity!)
  "cgroup": 686846,
  "freq": 3
}
```

**Identity**: `(inode, ps_type, cgroup)` - **NOT PID**
- Same binary executed 3x = freq 3 (PIDs differ but identity same)

## Common Issues

### 1. No Events Captured
**Problem**: eBPF output is empty or very sparse
**Solution**:
- Check eBPF tool is running before workload
- Verify cgroup path is correct
- Ensure workload runs in target cgroup

### 2. Frequency Mismatches
**Problem**: `ebpf_freq != ground_truth_freq`
**Expected**: `ebpf_freq >= ground_truth_freq`
**Why**: System libraries may make additional calls

### 3. Too Many Missed Events
**Problem**: Accuracy < 80%
**Solutions**:
- Check for "Lost events" warning in eBPF output
- Increase perf buffer size
- Ensure workload completes before export
- Check event filtering logic

### 4. Can't Compare - File Not Found
**Problem**: `events.json` doesn't exist
**Solution**:
- Check your eBPF tool's export timing
- Look for `final-events.json` instead
- Verify export path in `manager.rs`

## Customization Examples

### Test Specific Network Endpoints
```python
# Edit test_workload.py - network_tests()
targets = [
    ('your-api.com', 443),
    ('database.local', 5432),
    ('cache.local', 6379),
]
for host, port in targets:
    # Make connection
    self.tracker.track_network_event(host, port, 'outgoing')
```

### Test Specific Files
```python
# Edit test_workload.py - fs_tests()
important_files = [
    '/etc/passwd',
    '/var/log/app.log',
    '/home/user/sensitive.txt'
]
for path in important_files:
    with open(path, 'r') as f:
        f.read()
    self.tracker.track_fs_event(path, 'read')
```

### Test Specific Processes
```python
# Edit test_workload.py - process_tests()
commands = [
    ['/usr/bin/wget', 'http://example.com'],
    ['/bin/bash', '-c', 'echo test'],
    ['/usr/bin/curl', 'https://api.example.com']
]
for cmd in commands:
    subprocess.run(cmd)
    self.tracker.track_process_event(cmd[0], 'execve', os.getpid())
```

## Next Steps

1. ✅ Run basic validation to establish baseline
2. 🎯 Add tests specific to your monitoring requirements
3. 🐛 If accuracy < 90%, debug with verbose logging
4. 🔄 Integrate into CI/CD pipeline
5. 📊 Create regression test suite

## Debug Mode

For detailed debugging:

```bash
# Run test with verbose Python
python3 -v test_workload.py ground_truth.json

# Run eBPF tool with debug logging
RUST_LOG=debug sudo cargo run --release

# Check for system-level issues
sudo dmesg | grep -i bpf
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

## Performance Benchmarking

```python
# Stress test with high event rate
# Modify test_workload.py
for i in range(10000):
    # High-frequency network
    sock = socket.create_connection(('1.1.1.1', 443))
    tracker.track_network_event('1.1.1.1', 443, 'outgoing')
    sock.close()
```

Check eBPF tool for:
- Lost events warnings
- Memory usage
- CPU usage
- Event processing latency






