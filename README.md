# eBPF Monitoring Tool

eBPF-based security monitoring tool for tracking network, filesystem, and process events in containers and cgroups.

## Quick Start

### Run Monitoring Tool
```bash
# Monitor specific Docker container
./run-ebpf.sh --container my-container

# Monitor custom cgroup
./run-ebpf.sh --cg-file /sys/fs/cgroup/system.slice/my-service.service

# Monitor host (default)
./run-ebpf.sh
```

### Run Validation Tests
```bash
cd test-harness
./docker_test.sh
```

---

## Documentation

| Document | Purpose |
|----------|---------|
| **[RUN_EBPF_GUIDE.md](RUN_EBPF_GUIDE.md)** | How to run the eBPF tool |
| **[test-harness/QUICKSTART.md](test-harness/QUICKSTART.md)** | Quick testing guide |
| **[test-harness/INDEX.md](test-harness/INDEX.md)** | Complete documentation index |

---

## What It Does

Monitors:
- **Network Events**: TCP/UDP connections (incoming/outgoing)
- **Filesystem Events**: File reads and writes
- **Process Events**: Process execution and forking

Outputs:
- Real-time console logging
- JSON export with event frequencies
- Deduplication by event identity

---

## Build Process

### Manual Build
```bash
# Step 1: Build eBPF bytecode
cd ebpf-mon-ebpf
cargo build --release

# Step 2: Run userspace tool
cd ../ebpf-mon
RUST_LOG=info cargo run --release \
  --config 'target."cfg(all())".runner="sudo -E"' \
  -- --cgroup /path/to/cgroup
```

### Automated Build (Recommended)
```bash
./run-ebpf.sh --container <container-name>
```
Builds and runs automatically!

---

## Testing & Validation

### Automated Docker Testing
```bash
cd test-harness
./docker_test.sh ./results

# View results
cat results/validation_report.txt
```

### Manual Testing
```bash
# Terminal 1: Start monitoring
./run-ebpf.sh --container test-app

# Terminal 2: Generate events
docker exec test-app python3 test-harness/test_workload.py test-harness/ground_truth.json

# Terminal 2: Compare results
cd test-harness
python3 compare_results.py ground_truth.json ../ebpf-mon/events.json
```

---

## Example Output

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
      "path": "/etc/hosts",
      "inode": 2625447,
      "owner_uid": 0,
      "r_w": "read",
      "freq": 1
    }
  ],
  "process": [
    {
      "exec_path": "/bin/bash",
      "inode": 2625684,
      "ps_type": "execve",
      "pid": 3621186,
      "cgroup": 686846,
      "freq": 1
    }
  ]
}
```

---

## Key Concepts

### Event Deduplication

Events are deduplicated by **identity keys**:

| Event Type | Identity Key |
|------------|--------------|
| Network | `(dst_ip, dst_port, direction)` |
| Filesystem | `(inode, r_w, owner_uid)` |
| Process | `(inode, ps_type, cgroup)` |

Multiple operations with same identity -> single event with `freq > 1`

### Cgroup Targeting

The tool monitors a specific cgroup (control group):
- **Container**: Monitor single Docker container
- **Service**: Monitor systemd service
- **System**: Monitor entire Docker/Kubernetes environment

---

## Requirements

- Linux kernel >= 5.4 (with eBPF support)
- Rust toolchain
- LLVM (for eBPF compilation)
- Docker (for container monitoring)

### Installation
```bash
# Ubuntu/Debian
sudo apt install llvm clang

# Rust toolchain
rustup target add bpfel-unknown-none

# Docker (optional, for container testing)
sudo apt install docker.io
```

---

## Project Structure

```
ebpf-mon/
├── run-ebpf.sh              # Unified build & run script ⭐
├── RUN_EBPF_GUIDE.md        # Script documentation
├── ebpf-mon-ebpf/           # eBPF kernel-space code
│   └── src/
│       ├── network.rs       # Network event tracking
│       ├── filesystem.rs    # FS event tracking
│       └── process.rs       # Process event tracking
├── ebpf-mon/                # Userspace Rust code
│   └── src/
│       ├── main.rs          # Entry point
│       └── manager.rs       # Event processing
├── ebpf-mon-common/         # Shared code (libraries)
└── test-harness/            # Testing framework
    ├── docker_test.sh       # Automated testing
    ├── test_workload.py     # Ground truth generator
    ├── compare_results.py   # Validation tool
    └── *.md                 # Documentation
```

---

## Troubleshooting

### "Permission denied"
-> Tool needs sudo (handled automatically by `run-ebpf.sh`)

### "Container not found"
```bash
# Check container exists
docker ps -a

# Use exact name
./run-ebpf.sh --container <exact-name>
```

### "Cgroup path does not exist"
```bash
# List available cgroups
ls -la /sys/fs/cgroup/

# Monitor all Docker containers
./run-ebpf.sh --cg-file /sys/fs/cgroup/system.slice/docker.service
```

### No events appearing
- Container must be actively doing things
- Check logs for errors
- Verify correct cgroup is targeted

---

## Use Cases

### Development
```bash
# Monitor during development
./run-ebpf.sh
# Your local processes will be monitored
```

### Container Security
```bash
# Monitor production container
./run-ebpf.sh --container production-app
# Detect anomalous behavior
```

### Testing & Validation
```bash
# Automated testing
cd test-harness
./docker_test.sh
# Ensure tool captures all events correctly
```

### CI/CD Integration
```bash
# In your pipeline
./run-ebpf.sh --cg-file /sys/fs/cgroup/docker &
EBPF_PID=$!
# Run tests...
kill $EBPF_PID
```

---

## Learn More

- **[RUN_EBPF_GUIDE.md](RUN_EBPF_GUIDE.md)** - Complete guide to running the tool
- **[test-harness/QUICKSTART.md](test-harness/QUICKSTART.md)** - Fast-track testing
- **[test-harness/INDEX.md](test-harness/INDEX.md)** - Full documentation index
- **[test-harness/DOCKER_SOLUTIONS.md](test-harness/DOCKER_SOLUTIONS.md)** - Container monitoring solutions

---

## License

See LICENSE files for details.
