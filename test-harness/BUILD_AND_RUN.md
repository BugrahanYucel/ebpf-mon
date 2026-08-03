# How to Build and Run eBPF Monitoring Tool

## ⚠️ Important: Correct Build Process

Your eBPF tool requires a **two-step build and run process**:

### Step 1: Build eBPF Bytecode
```bash
cd /home/bugrahanyucel/infrasec/projects/ebpf-mon/ebpf-mon-ebpf
cargo build --release
```

**What this does:**
- Compiles the eBPF kernel-space code
- Creates `.o` files that will be loaded into the kernel
- Must be done before running the userspace tool

### Step 2: Run Userspace Tool
```bash
cd /home/bugrahanyucel/infrasec/projects/ebpf-mon/ebpf-mon
RUST_LOG=info cargo run --release \
  --config 'target."cfg(all())".runner="sudo -E"' \
  -- --cgroup /sys/fs/cgroup/path/to/cgroup
```

**What this does:**
- Runs the userspace Rust program with sudo privileges
- The `--config` option tells cargo to use `sudo -E` as the runner
- The `-E` flag preserves environment variables (including `RUST_LOG`)
- Passes `--cgroup` argument to your program

---

## 🚀 Quick Commands

### For Host Testing
```bash
# Build (one-time, or when code changes)
cd ebpf-mon-ebpf && cargo build --release && cd ..

# Run
cd ebpf-mon
RUST_LOG=info cargo run --release \
  --config 'target."cfg(all())".runner="sudo -E"' \
  -- --cgroup /sys/fs/cgroup/user.slice
```

### For Docker Testing (Manual)
```bash
# 1. Start container
docker run -d --name test -v $(pwd)/test-harness:/workload python:3.9 sleep infinity

# 2. Get cgroup
CGROUP_ID=$(docker inspect test -f '{{.Id}}')
CGROUP_PATH="/sys/fs/cgroup/system.slice/docker-${CGROUP_ID}.scope"

# 3. Build and run eBPF tool
cd ebpf-mon-ebpf && cargo build --release && cd ../ebpf-mon
RUST_LOG=info cargo run --release \
  --config 'target."cfg(all())".runner="sudo -E"' \
  -- --cgroup $CGROUP_PATH

# 4. Run workload (in another terminal)
docker exec test python3 /workload/test_workload.py /workload/ground_truth.json
```

### For Docker Testing (Automated)
```bash
cd test-harness
./docker_test.sh
```
The script handles all build and run steps automatically!

---

## 📝 Environment Variables

### RUST_LOG
Controls logging verbosity:
```bash
RUST_LOG=info     # Standard logging (recommended)
RUST_LOG=debug    # Verbose debugging
RUST_LOG=trace    # Very verbose (for deep debugging)
RUST_LOG=error    # Only errors
```

### EBPF_DIR
For the automated script, you can override the eBPF directory:
```bash
EBPF_DIR=/path/to/ebpf-mon ./docker_test.sh
```

---

## 🔧 Why This Build Process?

### Why Two Steps?

1. **eBPF Bytecode (Kernel Space)**
   - Built in `ebpf-mon-ebpf/`
   - Compiles to BPF bytecode (`.o` files)
   - Runs IN the kernel
   - No sudo needed for build

2. **Userspace Tool (User Space)**
   - Built in `ebpf-mon/`
   - Loads eBPF bytecode into kernel
   - Reads events from eBPF programs
   - **Needs sudo** to load into kernel

### Why `--config 'target."cfg(all())".runner="sudo -E"'`?

This tells cargo to:
- Run the final binary with `sudo`
- Use `-E` to preserve environment variables
- Allows `RUST_LOG` to work even with sudo

**Alternative (without config):**
```bash
# Build first
cargo build --release

# Run with sudo
sudo RUST_LOG=info ./target/release/ebpf-mon --cgroup /path
```

But the config approach is cleaner for development.

---

## 🐛 Troubleshooting

### "Permission denied" errors
**Cause:** eBPF requires root privileges to load into kernel

**Solution:** Ensure you're using the `--config 'target."cfg(all())".runner="sudo -E"'` option

### "RUST_LOG not working"
**Cause:** `sudo` doesn't preserve environment variables by default

**Solution:** Use `-E` flag: `sudo -E` or use the cargo config

### "Cannot find eBPF object file"
**Cause:** eBPF bytecode not built

**Solution:** Run `cd ebpf-mon-ebpf && cargo build --release` first

### "error: linker `llvm-objcopy` not found"
**Cause:** Missing LLVM tools for eBPF compilation

**Solution:** 
```bash
# Ubuntu/Debian
sudo apt install llvm

# Other systems - check your package manager
```

---

## 📚 Integration with Test Harness

All test harness scripts now use the correct build process:

### ✅ Updated Files
- `docker_test.sh` - Automated Docker testing
- `QUICKSTART.md` - Quick start commands
- `DOCKER_SOLUTIONS.md` - Docker problem solutions
- `BUILD_AND_RUN.md` - This file

### How Scripts Handle Building

The automated `docker_test.sh` script:
1. Builds eBPF bytecode first
2. Then runs the userspace tool with proper cargo command
3. Captures any build errors
4. Logs everything for debugging

---

## 🎯 Best Practices

### Development Workflow
```bash
# 1. Make changes to eBPF code
vim ebpf-mon-ebpf/src/*.rs

# 2. Rebuild eBPF bytecode
cd ebpf-mon-ebpf && cargo build --release && cd ..

# 3. Make changes to userspace code
vim ebpf-mon/src/*.rs

# 4. Run with live reload (no need to rebuild eBPF if unchanged)
cd ebpf-mon
RUST_LOG=debug cargo run --release \
  --config 'target."cfg(all())".runner="sudo -E"' \
  -- --cgroup /sys/fs/cgroup/user.slice
```

### Testing Workflow
```bash
# Quick test with automated script
cd test-harness
./docker_test.sh

# Or manual testing for more control
# (see "For Docker Testing (Manual)" above)
```

### CI/CD Workflow
```bash
#!/bin/bash
# .github/workflows/test.sh

set -e

# Build eBPF
cd ebpf-mon-ebpf
cargo build --release
cd ..

# Build userspace
cd ebpf-mon
cargo build --release
cd ..

# Run tests
cd test-harness
sudo ./docker_test.sh ./results

# Check accuracy
accuracy=$(grep "Overall Accuracy" results/validation_report.txt | cut -d: -f2)
if (( $(echo "$accuracy < 90" | bc -l) )); then
    echo "Accuracy too low: $accuracy%"
    exit 1
fi
```

---

## 🔗 Related Documentation

- **QUICKSTART.md** - Fast commands for immediate testing
- **DOCKER_SOLUTIONS.md** - Solving container ID problems
- **README.md** - Complete test harness documentation
- **INDEX.md** - Navigation to all docs

---

## 💡 Quick Reference Card

```bash
# Essential Commands (copy-paste friendly)

# Build eBPF bytecode
cd ebpf-mon-ebpf && cargo build --release && cd ..

# Run eBPF tool (host testing)
cd ebpf-mon && RUST_LOG=info cargo run --release \
  --config 'target."cfg(all())".runner="sudo -E"' \
  -- --cgroup /sys/fs/cgroup/user.slice

# Run eBPF tool (Docker testing) - automated
cd test-harness && ./docker_test.sh

# Check if eBPF bytecode is up to date
ls -lh ebpf-mon-ebpf/target/bpfel-unknown-none/release/*.o

# Watch eBPF tool logs
tail -f test-harness/validation_results/ebpf_output.log
```


