# Test Harness Workflow

## 📊 Visual Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                     VALIDATION WORKFLOW                          │
└─────────────────────────────────────────────────────────────────┘

Step 1: Generate Ground Truth
┌───────────────────┐
│  test_workload.py │ ──> Performs controlled operations
└─────────┬─────────┘     • Network connections
          │               • File read/write
          │               • Process exec/fork
          │
          ├──> Tracks identity keys:
          │    • Network: (dst_ip, dst_port, direction)
          │    • FS: (inode, r_w, owner_uid)
          │    • Process: (inode, ps_type, cgroup)
          │
          └──> Outputs JSON
               ┌──────────────────┐
               │ ground_truth.json │
               └──────────────────┘

Step 2: eBPF Tool Captures Events
┌──────────────┐
│  eBPF Tool   │ ──> Monitors same operations
└──────┬───────┘     • Attaches to cgroup
       │             • Captures at kernel level
       │             • Deduplicates by identity
       │
       └──> Exports events periodically
            ┌──────────────┐
            │  events.json │
            └──────────────┘

Step 3: Compare & Validate
┌────────────────────┐     ┌──────────────────┐
│  ground_truth.json │ ──> │ compare_results.py│
└────────────────────┘     └─────────┬─────────┘
┌──────────────┐                    │
│ events.json  │ ───────────────────┘
└──────────────┘                    │
                                    │
                     Compares event identities
                     Validates frequencies
                     Reports metrics
                                    │
                                    ▼
                        ┌────────────────────┐
                        │ VALIDATION REPORT  │
                        │ • Matched events   │
                        │ • Missed events    │
                        │ • Extra events     │
                        │ • Accuracy %       │
                        └────────────────────┘
```

---

## 🔄 Detailed Flow

### Phase 1: Setup

```
┌─────────┐
│ START   │
└────┬────┘
     │
     ├─> Build eBPF tool
     │   cd /path/to/ebpf-mon
     │   cargo build --release
     │
     └─> Start eBPF monitoring
         sudo ./target/release/ebpf-mon --cgroup <path>
         ⏱️  Wait for attachment...
```

### Phase 2: Ground Truth Generation

```
┌──────────────────┐
│  test_workload   │
└────────┬─────────┘
         │
         ├─> Network Tests
         │   │
         │   ├─> socket.connect('1.1.1.1', 443)  [Operation]
         │   └─> tracker.track_network_event()    [Ground Truth]
         │
         ├─> Filesystem Tests
         │   │
         │   ├─> open('/tmp/test.txt', 'r').read() [Operation]
         │   └─> tracker.track_fs_event()          [Ground Truth]
         │
         └─> Process Tests
             │
             ├─> subprocess.run(['/bin/echo'])     [Operation]
             └─> tracker.track_process_event()     [Ground Truth]
```

### Phase 3: eBPF Capture

```
┌──────────────────────────────────────────┐
│         Kernel Space (eBPF)              │
├──────────────────────────────────────────┤
│                                          │
│  Network Hook (cgroup_skb)               │
│  ├─> Intercepts socket operations       │
│  ├─> Extracts (dst_ip, dst_port, dir)   │
│  └─> Sends to perf buffer               │
│                                          │
│  FS Hook (fentry/vfs_read, vfs_write)    │
│  ├─> Intercepts VFS operations          │
│  ├─> Extracts (inode, r_w, owner_uid)   │
│  └─> Sends to perf buffer               │
│                                          │
│  Process Hook (sched_process_exec/fork)  │
│  ├─> Intercepts process creation        │
│  ├─> Extracts (inode, ps_type, cgroup)  │
│  └─> Sends to perf buffer               │
│                                          │
└──────────────┬───────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────┐
│         User Space (Rust)                │
├──────────────────────────────────────────┤
│                                          │
│  listen_all_events()                     │
│  ├─> Reads from perf buffer             │
│  └─> Sends to channel                   │
│                                          │
│  simple_event_reader()                   │
│  ├─> Receives events from channel       │
│  ├─> Deduplicates by identity          │
│  ├─> Updates EventMap with freq         │
│  └─> Logs to console                    │
│                                          │
│  export_events_to_json()                 │
│  └─> Periodic export (every 10-60s)     │
│                                          │
└──────────────┬───────────────────────────┘
               │
               ▼
         events.json
```

### Phase 4: Comparison

```
┌─────────────────┐     ┌─────────────────┐
│ ground_truth    │     │  ebpf_output    │
│ {               │     │  {              │
│   network: [    │     │    network: [   │
│     {dst_ip:..  │     │      {dst_ip:.. │
│      freq: 5}   │     │       freq: 5}  │
│   ]             │     │    ]            │
│ }               │     │  }              │
└────────┬────────┘     └────────┬────────┘
         │                       │
         └───────────┬───────────┘
                     │
                     ▼
           ┌─────────────────────┐
           │ compare_results.py  │
           └──────────┬──────────┘
                      │
        ┌─────────────┼─────────────┐
        │             │             │
        ▼             ▼             ▼
   ┌────────┐   ┌─────────┐   ┌────────┐
   │Matched │   │ Missed  │   │ Extra  │
   │  ✓     │   │   ✗     │   │   ⚠    │
   └────────┘   └─────────┘   └────────┘
        │             │             │
        └─────────────┴─────────────┘
                      │
                      ▼
            ┌──────────────────┐
            │  Accuracy Report │
            │  • Network: 100% │
            │  • FS: 95%       │
            │  • Process: 98%  │
            │  Overall: 97%    │
            └──────────────────┘
```

---

## 🎯 Event Identity Matching

### How Events Are Matched

```
Ground Truth Event              eBPF Captured Event
┌────────────────────┐         ┌────────────────────┐
│ dst_ip: "1.1.1.1"  │         │ dst_ip: "1.1.1.1"  │
│ dst_port: 443      │  ═══►   │ dst_port: 443      │
│ direction: "out"   │         │ direction: "out"   │
│ freq: 5            │         │ freq: 5            │
└────────────────────┘         └────────────────────┘
         │                              │
         └──────────┬───────────────────┘
                    │
                    ▼
           ┌────────────────┐
           │  Identity Key: │
           │  (dst_ip=1.1.1.1, dst_port=443, dir=1)
           └────────────────┘
                    │
                    ▼
              MATCH FOUND ✓
         (Both have same identity + freq)
```

### Deduplication Model

```
Multiple operations -> Single event with frequency

Operation 1: connect('1.1.1.1', 443)  ──┐
Operation 2: connect('1.1.1.1', 443)  ──┤
Operation 3: connect('1.1.1.1', 443)  ──┼──> Identity: (1.1.1.1, 443, out)
Operation 4: connect('1.1.1.1', 443)  ──┤    Frequency: 5
Operation 5: connect('1.1.1.1', 443)  ──┘

Result in JSON:
{
  "dst_ip": "1.1.1.1",
  "dst_port": 443,
  "direction": "outgoing",
  "freq": 5          ← Incremented for each operation
}
```

---

## 🔍 Decision Tree: Interpreting Results

```
                  ┌──────────────┐
                  │ Run Test     │
                  └──────┬───────┘
                         │
                         ▼
                  ┌──────────────┐
              ┌───│   Results    │───┐
              │   └──────────────┘   │
              │                      │
    ┌─────────▼─────────┐   ┌───────▼────────┐
    │ Accuracy > 95%?   │   │  Lost Events?  │
    └─────────┬─────────┘   └───────┬────────┘
              │                     │
        ┌─────┴─────┐         ┌─────┴─────┐
        │           │         │           │
       YES         NO        YES         NO
        │           │         │           │
        ▼           │         ▼           ▼
    ┌────────┐      │    ┌─────────┐  ┌──────────┐
    │SUCCESS!│      │    │Increase │  │Check for │
    │   ✅   │      │    │ Buffer  │  │ Timing   │
    └────────┘      │    │  Size   │  │ Issues   │
                    │    └─────────┘  └──────────┘
                    ▼
          ┌──────────────────┐
          │ Accuracy 80-95%? │
          └─────────┬────────┘
                    │
              ┌─────┴─────┐
              │           │
             YES         NO
              │           │
              ▼           ▼
         ┌─────────┐  ┌──────────┐
         │  GOOD   │  │  DEBUG   │
         │Review   │  │Enable    │
         │Missed   │  │Verbose   │
         │Events   │  │Logging   │
         └─────────┘  └──────────┘
```

---

## ⚙️ Configuration Points

```
Test Harness Configuration
┌─────────────────────────────────────┐
│ test_workload.py                    │
├─────────────────────────────────────┤
│ • Number of operations per test     │
│ • Target IPs/ports for network      │
│ • File paths for FS tests           │
│ • Binaries for process tests        │
│ • Test timeout values               │
└─────────────────────────────────────┘

eBPF Tool Configuration
┌─────────────────────────────────────┐
│ manager.rs                          │
├─────────────────────────────────────┤
│ Line 27: Perf buffer size           │
│   .open(cpu_id, Some(128))          │
│   Increase if losing events         │
└─────────────────────────────────────┘
┌─────────────────────────────────────┐
│ main.rs                             │
├─────────────────────────────────────┤
│ Line 147: Export interval           │
│   Duration::from_secs(10)           │
│   Adjust for faster/slower export   │
└─────────────────────────────────────┘
```

---

## 🎓 Learning Path Flowchart

```
                    START
                      │
                      ▼
        ┌──────────────────────────┐
        │  Read QUICKSTART.md      │ ← 5 minutes
        └──────────┬───────────────┘
                   │
                   ▼
        ┌──────────────────────────┐
        │  Run Basic Test          │
        │  • Start eBPF tool       │
        │  • Run test_workload     │
        │  • Compare results       │
        └──────────┬───────────────┘
                   │
            ┌──────┴──────┐
            │             │
       Good Result   Bad Result
            │             │
            ▼             ▼
    ┌──────────────┐  ┌──────────────────┐
    │Read Summary  │  │Read              │
    │& Examples    │  │EXAMPLE_OUTPUT.md │
    └──────┬───────┘  └────────┬─────────┘
           │                   │
           │                   ▼
           │          ┌──────────────────┐
           │          │ Troubleshoot &   │
           │          │ Fix Issues       │
           │          └────────┬─────────┘
           │                   │
           └───────────────────┘
                      │
                      ▼
           ┌──────────────────────┐
           │ Customize for Your   │
           │ Use Case             │
           └──────────┬───────────┘
                      │
                      ▼
           ┌──────────────────────┐
           │ Integrate into       │
           │ Development Workflow │
           └──────────────────────┘
                      │
                      ▼
                   DONE!
```

---

## 📈 Metrics Dashboard (Conceptual)

```
╔═══════════════════════════════════════════════════════════╗
║              VALIDATION DASHBOARD                         ║
╠═══════════════════════════════════════════════════════════╣
║                                                           ║
║  Overall Accuracy:  ████████████████████░ 95%  ✅        ║
║                                                           ║
║  Network Events:    ██████████████████████ 100%  ✅      ║
║  ├─ Matched: 7/7                                         ║
║  ├─ Missed: 0                                            ║
║  └─ Extra: 5 (normal background activity)                ║
║                                                           ║
║  Filesystem Events: ███████████████████░░ 92%   ✓        ║
║  ├─ Matched: 12/13                                       ║
║  ├─ Missed: 1 (/etc/hosts read)                         ║
║  └─ Extra: 77 (Python runtime, system libs)             ║
║                                                           ║
║  Process Events:    ██████████████████████ 100%  ✅      ║
║  ├─ Matched: 5/5                                         ║
║  ├─ Missed: 0                                            ║
║  └─ Extra: 13 (shell spawns, system processes)          ║
║                                                           ║
║  Lost Events: 0                                   ✅      ║
║  Buffer Overflows: 0                              ✅      ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝

Action Items:
• ✅ Production ready
• 📝 Document baseline metrics
• 🔄 Add to CI/CD pipeline
```

---

## 🔄 Continuous Testing Workflow

```
┌──────────────────────────────────────────────────────┐
│                  CI/CD Pipeline                      │
└──────────────────────────────────────────────────────┘

  git push
      │
      ▼
  ┌─────────┐
  │ Build   │ cargo build --release
  └────┬────┘
       │
       ▼
  ┌─────────┐
  │  Test   │
  └────┬────┘
       │
       ├──► Unit tests (cargo test)
       │
       ├──► eBPF validation tests
       │    │
       │    ├─ Start eBPF tool
       │    ├─ Run test workload
       │    ├─ Compare results
       │    └─ Assert accuracy > 90%
       │
       └──► Integration tests
            │
            └─ Docker container tests
               │
               └─ Kubernetes pod tests

       ▼
  ┌─────────┐
  │ Deploy  │ if all tests pass
  └─────────┘
```

---

## 🎯 Quick Reference

### Files to Start With
1. **QUICKSTART.md** - Run your first test (3 commands)
2. **EXAMPLE_OUTPUT.md** - Understand what you see
3. **TEST_HARNESS_SUMMARY.md** - Learn key concepts

### Commands to Remember
```bash
# Generate ground truth
python3 test_workload.py ground_truth.json

# Compare results  
python3 compare_results.py ground_truth.json events.json

# Docker test
docker run --rm -v $(pwd):/output ebpf-test
```

### Key Concepts
- **Identity Keys** determine event uniqueness
- **Frequency** counts repeated operations
- **Extra Events** are normal (system activity)
- **Missed Events** indicate problems

---

**Ready to start?** -> Open [QUICKSTART.md](QUICKSTART.md) 🚀







