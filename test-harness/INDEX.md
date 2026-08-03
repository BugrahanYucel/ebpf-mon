# Test Harness Documentation Index

## 🚀 Start Here

New to the test harness? Read files in this order:

1. **[QUICKSTART.md](QUICKSTART.md)** ⭐ START HERE
   - 5-minute quick start
   - Essential commands
   - Common issues

2. **[TEST_HARNESS_SUMMARY.md](TEST_HARNESS_SUMMARY.md)** 
   - Complete overview
   - Key concepts
   - Best practices

3. **[EXAMPLE_OUTPUT.md](EXAMPLE_OUTPUT.md)**
   - What success looks like
   - How to interpret results
   - Debugging guidance

4. **[README.md](README.md)**
   - Detailed documentation
   - Customization guide
   - Troubleshooting

---

## 📂 Files Overview

### Executable Scripts

| File | Purpose | Usage |
|------|---------|-------|
| `test_workload.py` | Generate ground truth | `python3 test_workload.py output.json` |
| `compare_results.py` | Validate results | `python3 compare_results.py gt.json ebpf.json` |
| `run_validation.sh` | Automated workflow | `./run_validation.sh [output_dir]` |
| `docker_test.sh` | Docker automation | `./docker_test.sh [output_dir]` ⭐ NEW |

### Documentation

| File | Content | For |
|------|---------|-----|
| `QUICKSTART.md` | Fast-track guide | Immediate testing |
| `BUILD_AND_RUN.md` | Build & run process | Correct commands ⭐ NEW |
| `TEST_HARNESS_SUMMARY.md` | Complete overview | Understanding system |
| `EXAMPLE_OUTPUT.md` | Sample outputs | Interpreting results |
| `README.md` | Full documentation | Detailed reference |
| `DOCKER_SOLUTIONS.md` | Docker problem solutions | Container testing ⭐ NEW |
| `WORKFLOW.md` | Visual workflow | Understanding flow |
| `INDEX.md` | This file | Navigation |

### Configuration

| File | Purpose |
|------|---------|
| `Dockerfile` | Containerized testing environment |

---

## 🎯 Use Cases

### "I want to test my eBPF tool right now"
-> Read **QUICKSTART.md** (3 minutes)
-> Run: `./docker_test.sh` (1 command!)
-> Done!

### "I want to understand how this works"
-> Read **TEST_HARNESS_SUMMARY.md** (10 minutes)
-> Understand key concepts
-> Run tests confidently

### "I got results but don't understand them"
-> Read **EXAMPLE_OUTPUT.md** (5 minutes)
-> Compare with your output
-> Identify issues

### "Docker container ID problem"
-> Read **DOCKER_SOLUTIONS.md** (5 minutes)
-> Use `./docker_test.sh` (automated!)
-> Problem solved

### "I want to customize tests for my use case"
-> Read **README.md** sections:
  - "Customizing Tests"
  - "Testing Specific Scenarios"
-> Modify `test_workload.py`

### "Something is wrong, need to debug"
-> Read **QUICKSTART.md** -> "Troubleshooting"
-> Read **README.md** -> "Troubleshooting"
-> Enable debug logging

### "How do I build/run the eBPF tool correctly?"
-> Read **BUILD_AND_RUN.md** (5 minutes)
-> Two-step process explained
-> Copy-paste commands ready

---

## 📖 Quick Reference

### Essential Commands

```bash
# Generate ground truth
python3 test_workload.py ground_truth.json

# Compare results
python3 compare_results.py ground_truth.json ../ebpf-mon/events.json

# Docker testing
docker build -t ebpf-test .
docker run --rm -v $(pwd):/output ebpf-test
```

### Key Metrics

- **Accuracy >95%**: Excellent ✅
- **Accuracy 80-95%**: Good ✓
- **Accuracy <80%**: Needs work ⚠️

### Event Identity Keys

- Network: `(dst_ip, dst_port, direction)`
- Filesystem: `(inode, r_w, owner_uid)`
- Process: `(inode, ps_type, cgroup)` ← Note: NOT pid!

---

## 🔗 Quick Links by Topic

### Testing
- Basic testing -> [QUICKSTART.md](QUICKSTART.md) § "TL;DR - Fast Testing"
- Docker testing -> [QUICKSTART.md](QUICKSTART.md) § "Docker Testing"
- Automated testing -> [README.md](README.md) § "Method 1: Automated Validation"

### Understanding Results
- Good results -> [EXAMPLE_OUTPUT.md](EXAMPLE_OUTPUT.md) § "Example 1"
- Bad results -> [EXAMPLE_OUTPUT.md](EXAMPLE_OUTPUT.md) § "Example 2"
- Frequency tracking -> [EXAMPLE_OUTPUT.md](EXAMPLE_OUTPUT.md) § "Example 3"
- Metrics -> [TEST_HARNESS_SUMMARY.md](TEST_HARNESS_SUMMARY.md) § "Interpreting Results"

### Customization
- Add tests -> [README.md](README.md) § "Customizing Tests"
- Custom workloads -> [TEST_HARNESS_SUMMARY.md](TEST_HARNESS_SUMMARY.md) § "Customization"
- High-frequency tests -> [QUICKSTART.md](QUICKSTART.md) § "Performance Testing"

### Debugging
- Common issues -> [QUICKSTART.md](QUICKSTART.md) § "Common Issues"
- Troubleshooting -> [README.md](README.md) § "Troubleshooting"
- Debug mode -> [QUICKSTART.md](QUICKSTART.md) § "Debug Mode"
- Lost events -> [TEST_HARNESS_SUMMARY.md](TEST_HARNESS_SUMMARY.md) § "Check Lost Events"

### Advanced
- CI/CD -> [TEST_HARNESS_SUMMARY.md](TEST_HARNESS_SUMMARY.md) § "CI/CD Pipeline"
- Kubernetes -> [TEST_HARNESS_SUMMARY.md](TEST_HARNESS_SUMMARY.md) § "Testing in Kubernetes"
- Performance -> [TEST_HARNESS_SUMMARY.md](TEST_HARNESS_SUMMARY.md) § "Performance Benchmarking"

---

## 🎓 Learning Path

### Beginner
1. Read [QUICKSTART.md](QUICKSTART.md)
2. Run basic test
3. Read [EXAMPLE_OUTPUT.md](EXAMPLE_OUTPUT.md)
4. Understand your results

### Intermediate  
1. Read [TEST_HARNESS_SUMMARY.md](TEST_HARNESS_SUMMARY.md)
2. Add custom tests
3. Test in Docker
4. Achieve >90% accuracy

### Advanced
1. Read [README.md](README.md) completely
2. Set up CI/CD
3. Create regression tests
4. Performance benchmarking

---

## 🆘 Help

### File Not Found Errors
-> Check paths in commands
-> Ensure scripts are executable: `chmod +x *.py *.sh`

### Low Accuracy
-> [EXAMPLE_OUTPUT.md](EXAMPLE_OUTPUT.md) § "Problems Detected"
-> [TEST_HARNESS_SUMMARY.md](TEST_HARNESS_SUMMARY.md) § "Common Issues"

### Understanding Output
-> [EXAMPLE_OUTPUT.md](EXAMPLE_OUTPUT.md)
-> [QUICKSTART.md](QUICKSTART.md) § "Understanding Output"

### Customization
-> [README.md](README.md) § "Customizing Tests"
-> [TEST_HARNESS_SUMMARY.md](TEST_HARNESS_SUMMARY.md) § "Customization"

---

## 📊 Cheat Sheet

### One-Liner Testing

```bash
# Complete test sequence
python3 test_workload.py gt.json && sleep 30 && python3 compare_results.py gt.json ../ebpf-mon/events.json
```

### Docker One-Liner

```bash
docker run --rm -v $(pwd):/output python:3.9 python3 /output/test_workload.py /output/gt.json
```

### Quick Accuracy Check

```bash
# Extract just the accuracy line
python3 compare_results.py gt.json events.json 2>/dev/null | grep "Overall Accuracy"
```

---

## ✅ Next Steps

After reading this index:

1. **First time?** -> Start with [QUICKSTART.md](QUICKSTART.md)
2. **Want details?** -> Read [TEST_HARNESS_SUMMARY.md](TEST_HARNESS_SUMMARY.md)
3. **Got results?** -> Compare with [EXAMPLE_OUTPUT.md](EXAMPLE_OUTPUT.md)
4. **Need reference?** -> Use [README.md](README.md)

**Happy Testing! 🚀**






