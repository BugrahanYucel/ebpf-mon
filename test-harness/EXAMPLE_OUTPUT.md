# Example Validation Output

This document shows what successful validation looks like.

## Example 1: Good Results (95%+ Accuracy)

```
======================================================================
eBPF MONITORING TOOL VALIDATION REPORT
======================================================================

======================================================================
NETWORK EVENTS COMPARISON
======================================================================

📊 Summary:
  Ground Truth: 7 unique events
  eBPF Captured: 12 unique events
  Matched: 7 ✓
  Missed: 0 ✗
  Extra (not in ground truth): 5 ⚠

✓ Matched Events (7):
  ✓ 1.1.1.1:443 (outgoing) - GT freq: 5, eBPF freq: 5
  ✓ 8.8.8.8:443 (outgoing) - GT freq: 1, eBPF freq: 1
  ✓ 8.8.8.8:80 (outgoing) - GT freq: 1, eBPF freq: 1
  ✓ 8.8.8.8:8080 (outgoing) - GT freq: 1, eBPF freq: 1
  ✓ 1.1.1.1:53 (outgoing) - GT freq: 3, eBPF freq: 3
  ✓ 93.184.216.34:443 (outgoing) - GT freq: 1, eBPF freq: 1
  ✓ 142.250.185.46:443 (outgoing) - GT freq: 1, eBPF freq: 1

⚠ Extra Events (5) - Captured by eBPF but not in ground truth:
  + 169.254.169.254:53 (outgoing) - freq: 4
  + 10.0.2.15:22 (incoming) - freq: 2
  + 127.0.0.1:6379 (outgoing) - freq: 1
  + 172.17.0.1:443 (outgoing) - freq: 1
  + 8.8.4.4:53 (outgoing) - freq: 1

======================================================================
FILESYSTEM EVENTS COMPARISON
======================================================================

📊 Summary:
  Ground Truth: 13 unique events
  eBPF Captured: 89 unique events
  Matched: 12 ✓
  Missed: 1 ✗
  Extra (not in ground truth): 77 ⚠

✓ Matched Events (12):
  ✓ /tmp/ebpf_test/test_read.txt (read) - GT freq: 5, eBPF freq: 5
  ✓ /tmp/ebpf_test/test_write.txt (write) - GT freq: 5, eBPF freq: 5
  ✓ /tmp/ebpf_test/test_rw.txt (read) - GT freq: 1, eBPF freq: 1
  ✓ /tmp/ebpf_test/test_rw.txt (write) - GT freq: 1, eBPF freq: 1
  ✓ /tmp/ebpf_test/file_0.txt (write) - GT freq: 1, eBPF freq: 1
  ✓ /tmp/ebpf_test/file_0.txt (read) - GT freq: 1, eBPF freq: 1
  ✓ /tmp/ebpf_test/file_1.txt (write) - GT freq: 1, eBPF freq: 1
  ✓ /tmp/ebpf_test/file_1.txt (read) - GT freq: 1, eBPF freq: 1
  ✓ /tmp/ebpf_test/file_2.txt (write) - GT freq: 1, eBPF freq: 1
  ✓ /tmp/ebpf_test/file_2.txt (read) - GT freq: 1, eBPF freq: 1
  ... and 2 more

✗ Missed Events (1):
  - /etc/hosts (read) - inode: 2623456, freq: 1

⚠ Extra Events (77) - Showing top 10:
  + /usr/lib/python3.9/lib-dynload/_json.so (read) - inode: 2891234, freq: 15
  + /usr/lib/x86_64-linux-gnu/libc.so.6 (read) - inode: 2623789, freq: 12
  + /proc/self/status (read) - inode: 4026532027, freq: 8
  + /tmp/pyc_cache/__pycache__/test.pyc (write) - inode: 2891567, freq: 3
  + /usr/lib/locale/locale-archive (read) - inode: 2623890, freq: 2
  + /dev/urandom (read) - inode: 6, freq: 1
  + /etc/ssl/certs/ca-certificates.crt (read) - inode: 2624123, freq: 1
  + /proc/sys/net/ipv4/tcp_syncookies (read) - inode: 4026532089, freq: 1
  + /sys/fs/cgroup/memory/memory.limit_in_bytes (read) - inode: 1053, freq: 1
  + /tmp/test_socket_12345 (write) - inode: 2891678, freq: 1
  ... and 67 more

======================================================================
PROCESS EVENTS COMPARISON
======================================================================

📊 Summary:
  Ground Truth: 5 unique events
  eBPF Captured: 18 unique events
  Matched: 5 ✓
  Missed: 0 ✗
  Extra (not in ground truth): 13 ⚠

✓ Matched Events (5):
  ✓ /bin/echo (execve) - GT freq: 3, eBPF freq: 3
  ✓ /bin/ls (execve) - GT freq: 1, eBPF freq: 1
  ✓ /bin/cat (execve) - GT freq: 1, eBPF freq: 1
  ✓ /bin/pwd (execve) - GT freq: 1, eBPF freq: 1
  ✓ /bin/sh (fork) - GT freq: 2, eBPF freq: 2

⚠ Extra Events (13):
  + /usr/bin/python3 (execve) - inode: 2891023, freq: 1
  + /bin/bash (fork) - inode: 2623456, freq: 5
  + /usr/bin/grep (execve) - inode: 2891234, freq: 1
  + /usr/lib/systemd/systemd-logind (fork) - inode: 2624567, freq: 1
  + /usr/bin/ssh (execve) - inode: 2891345, freq: 1
  ... and 8 more

======================================================================
OVERALL VALIDATION SUMMARY
======================================================================

📈 Overall Statistics:
  Total Ground Truth Events: 25
  Total Matched: 24 (96.0%)
  Total Missed: 1 (4.0%)
  Total Extra: 95

  Overall Accuracy: 96.00%

📊 Per-Category Accuracy:
  Network:  100.0%
  Filesystem: 92.3%
  Process:  100.0%

======================================================================
✅ EXCELLENT: Tool captures >95% of ground truth events
======================================================================

ℹ Note: 95 extra events were captured by eBPF.
  This is normal - the tool captures system background activity.
  Focus on ensuring ground truth events are NOT in the 'missed' category.
```

**Analysis**: This is excellent! 96% accuracy with only 1 missed event. Extra events are expected system activity.

---

## Example 2: Problems Detected (70% Accuracy)

```
======================================================================
NETWORK EVENTS COMPARISON
======================================================================

📊 Summary:
  Ground Truth: 7 unique events
  eBPF Captured: 4 unique events
  Matched: 4 ✓
  Missed: 3 ✗
  Extra (not in ground truth): 0 ⚠

✓ Matched Events (4):
  ✓ 1.1.1.1:443 (outgoing) - GT freq: 5, eBPF freq: 3
  ✓ 8.8.8.8:443 (outgoing) - GT freq: 1, eBPF freq: 1
  ✓ 8.8.8.8:80 (outgoing) - GT freq: 1, eBPF freq: 1
  ✓ 1.1.1.1:53 (outgoing) - GT freq: 3, eBPF freq: 2

✗ Missed Events (3):
  - 8.8.8.8:8080 (outgoing) - freq: 1
  - 93.184.216.34:443 (outgoing) - freq: 1
  - 142.250.185.46:443 (outgoing) - freq: 1

======================================================================
OVERALL VALIDATION SUMMARY
======================================================================

📈 Overall Statistics:
  Total Ground Truth Events: 25
  Total Matched: 17 (68.0%)
  Total Missed: 8 (32.0%)
  Total Extra: 2

  Overall Accuracy: 68.00%

📊 Per-Category Accuracy:
  Network:  57.1%
  Filesystem: 75.0%
  Process:  80.0%

======================================================================
⚠ FAIR: Tool captures >60% of ground truth events - review missed events
======================================================================
```

**Problems Identified**:
1. **Frequency mismatches**: `eBPF freq < GT freq` indicates lost events
2. **Missed events**: Several connections not captured at all
3. **Network accuracy low**: Only 57.1% of network events captured

**Debugging Steps**:
1. Check for "Lost events" warnings in eBPF output
2. Increase perf buffer size
3. Check if workload runs too fast
4. Verify cgroup filtering is correct

---

## Example 3: Frequency Tracking Validation

This example demonstrates proper frequency tracking:

```
✓ Matched Events:
  ✓ 1.1.1.1:443 (outgoing) - GT freq: 5, eBPF freq: 5  ← Perfect match
  ✓ /tmp/test.txt (read) - GT freq: 10, eBPF freq: 10  ← Perfect match
  ✓ /bin/echo (execve) - GT freq: 3, eBPF freq: 3      ← Perfect match
```

**What This Means**:
- ✅ Deduplication works correctly
- ✅ Frequency counter increments properly
- ✅ Multiple operations to same identity are tracked as one event with freq > 1

```
✗ Frequency Mismatches:
  ✗ 8.8.8.8:443 (outgoing) - GT freq: 5, eBPF freq: 3  ← Lost 2 events!
  ✗ /tmp/log.txt (write) - GT freq: 100, eBPF freq: 75 ← Lost 25 events!
```

**Problems**:
- ❌ Events are being lost (buffer overflow or processing lag)
- ❌ Check eBPF perf buffer logs for warnings

---

## Interpreting Extra Events

### Normal Extra Events (Expected)

```
⚠ Extra Events:
  + /usr/lib/x86_64-linux-gnu/libc.so.6 (read) - System library
  + /proc/self/status (read) - Process introspection
  + /usr/lib/python3.9/lib-dynload/_json.so (read) - Python runtime
  + /etc/ssl/certs/ca-certificates.crt (read) - SSL initialization
  + /sys/fs/cgroup/memory/memory.limit_in_bytes (read) - Cgroup queries
```

**Why**: Python interpreter and system libraries make many implicit calls

**Action**: None needed - this is expected behavior

### Suspicious Extra Events (Investigate)

```
⚠ Extra Events:
  + /etc/shadow (read) - Unusual file access
  + /root/.ssh/id_rsa (read) - Sensitive file
  + 192.168.1.100:31337 (outgoing) - Unusual port
  + /tmp/.hidden_backdoor (execve) - Suspicious binary
```

**Why**: Either legitimate background activity or actual security issues

**Action**: Investigate - could be real threats or misconfigured test environment

---

## Key Metrics to Watch

### ✅ Good Signs
- Overall accuracy > 90%
- Matched events have correct frequencies
- Missed events = 0 or very few
- Extra events are mostly system libraries

### ⚠️ Warning Signs
- Accuracy 70-90%
- Some frequency mismatches
- A few missed events
- Check for tuning opportunities

### ❌ Problems
- Accuracy < 70%
- Many frequency mismatches (eBPF < GT)
- Many missed events
- Check for lost events, buffer size, timing issues

---

## Next Steps After Validation

### If Accuracy > 95%
✅ Tool is working well
- Add domain-specific tests
- Integrate into CI/CD
- Run in production with monitoring

### If Accuracy 80-95%
⚠️ Minor issues
- Review missed events
- Check buffer configuration
- Test with different workload patterns

### If Accuracy < 80%
❌ Needs investigation
- Enable debug logging
- Check for lost events
- Verify eBPF attachment timing
- Review event filtering logic
- Test with minimal workload first







