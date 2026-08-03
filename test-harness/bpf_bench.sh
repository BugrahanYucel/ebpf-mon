#!/usr/bin/env bash
#
# bpf_bench.sh — per-program eBPF cost + workload timing for ebpf-mon.
#
# Standalone: touches nothing in the project. Uses `bpftool` kernel BPF stats
# to measure real average per-program run time (ns/run) around a workload, so
# you can compare baseline / monitor-only / enforcing and optimized vs
# unoptimized policies.
#
# Requires: sudo, bpftool, python3.
#
# Usage:
#   sudo ./bpf_bench.sh profile <seconds>         # measure over a window while you drive load manually
#   sudo ./bpf_bench.sh profile-cmd "<command>"   # measure around a command
#   ./bpf_bench.sh workload-open   <dir> <iters>  # load generator: repeated open()
#   ./bpf_bench.sh workload-exec   <iters>        # load generator: repeated exec()
#   ./bpf_bench.sh workload-connect <host> <port> <iters>   # load generator: repeated connect()
#   sudo ./bpf_bench.sh policy-footprint                     # per-map used-entry counts (opt vs no-opt)
#
# Tip: run a workload-* generator INSIDE the monitored container, e.g.
#   docker exec <ctr> bash -s < bpf_bench.sh workload-open /etc 20000
set -euo pipefail

# ebpf-mon program names. NOTE: the kernel truncates BPF prog names to 15 chars
# (BPF_OBJ_NAME_LEN-1), so matching is done on the 15-char prefix.
EBPF_MON_PROGS=(
  vfs_open_fexit vfs_write_fentry vfs_write_fexit vfs_read_fentry vfs_read_fexit
  check_symlink vfs_iter_write_fentry vfs_iter_write_fexit vfs_iter_read_fentry
  vfs_iter_read_fexit cgroup_skb_egress cgroup_skb_ingress docker_proxy_accept
  docker_proxy_connect execve_tracepoint execveat_tracepoint exit_execve_tracepoint
  exit_execveat_tracepoint fork_tracepoint enforce_file_open enforce_bprm_check
  enforce_socket_connect
)

need() { command -v "$1" >/dev/null 2>&1 || { echo "error: '$1' is required" >&2; exit 1; }; }

snapshot() { bpftool -j prog show > "$1" 2>/dev/null; }

report_delta() {
  # $1 = before json, $2 = after json
  python3 - "$1" "$2" "${EBPF_MON_PROGS[@]}" <<'PY'
import json, sys
before_f, after_f = sys.argv[1], sys.argv[2]
names = sys.argv[3:]
prefixes = {n[:15] for n in names}   # kernel truncates to 15 chars

def load(p):
    with open(p) as fh:
        return {e["id"]: e for e in json.load(fh) if "id" in e}

b, a = load(before_f), load(after_f)
rows = []
for pid, ae in a.items():
    name = ae.get("name", "")
    if name not in prefixes:
        continue
    be = b.get(pid, {})
    d_cnt  = ae.get("run_cnt", 0)      - be.get("run_cnt", 0)
    d_time = ae.get("run_time_ns", 0)  - be.get("run_time_ns", 0)
    if d_cnt <= 0:
        continue
    rows.append((name, d_cnt, d_time, d_time / d_cnt))

rows.sort(key=lambda r: r[3], reverse=True)
print(f"{'program':<18}{'runs':>12}{'total_ns':>16}{'avg_ns/run':>14}")
print("-" * 60)
for name, cnt, tot, avg in rows:
    print(f"{name:<18}{cnt:>12}{tot:>16}{avg:>14.1f}")
if not rows:
    print("(no ebpf-mon programs were invoked during the window)")
PY
}

with_stats() {
  # Enables BPF stats, runs "$@", captures before/after, restores state.
  need bpftool; need python3
  local prev; prev=$(cat /proc/sys/kernel/bpf_stats_enabled 2>/dev/null || echo 0)
  sysctl -qw kernel.bpf_stats_enabled=1
  local before after; before=$(mktemp); after=$(mktemp)
  snapshot "$before"
  "$@"
  snapshot "$after"
  sysctl -qw kernel.bpf_stats_enabled="$prev"
  echo; report_delta "$before" "$after"
  rm -f "$before" "$after"
}

# Full names of the enforcement policy maps. The kernel truncates BPF map names to
# 15 chars (BPF_OBJ_NAME_LEN-1), so matching is done on the 15-char prefix.
POLICY_MAPS=(
  FILE_PATH_POLICY FILE_PATTERN_POLICY FILE_PREFIX_POLICY
  EXEC_PATH_POLICY EXEC_PATTERN_POLICY NET_CONNECT_POLICY
)

policy_footprint() {
  # Counts *used* entries per policy map (not max_entries). Fewer used entries in
  # the optimized run vs --no-optimize is the external proof the passes shrank the
  # policy. Run this while ebpf-mon is loaded (optimized), record it, then re-run
  # with a --no-optimize instance and compare.
  need bpftool; need python3
  python3 - "${POLICY_MAPS[@]}" <<'PY'
import json, subprocess, sys
names = sys.argv[1:]
prefixes = {n[:15]: n for n in names}   # kernel truncates to 15 chars

def bpftool(*args):
    out = subprocess.run(["bpftool", "-j", *args], capture_output=True, text=True)
    if out.returncode != 0 or not out.stdout.strip():
        return None
    return json.loads(out.stdout)

maps = bpftool("map", "show") or []
rows = []
for m in maps:
    nm = m.get("name", "")
    full = prefixes.get(nm)
    if not full:
        continue
    mid = m.get("id")
    dump = bpftool("map", "dump", "id", str(mid))
    used = len(dump) if isinstance(dump, list) else 0
    rows.append((full, m.get("max_entries", 0), used, m.get("bytes_memlock", 0)))

rows.sort()
print(f"{'policy map':<22}{'used':>8}{'max':>10}{'memlock_B':>12}")
print("-" * 52)
if not rows:
    print("(no policy maps found — is ebpf-mon running with --enforce?)")
for name, mx, used, mem in rows:
    print(f"{name:<22}{used:>8}{mx:>10}{mem:>12}")
PY
}

case "${1:-}" in
  policy-footprint)
    policy_footprint ;;
  profile)
    with_stats sleep "${2:?seconds required}" ;;
  profile-cmd)
    with_stats bash -c "${2:?command required}" ;;
  workload-open)
    dir="${2:?dir required}"; n="${3:-10000}"
    python3 -c "import os,sys
d,n=sys.argv[1],int(sys.argv[2])
fs=[os.path.join(d,f) for f in os.listdir(d)][:64] or [d]
for i in range(n):
    p=fs[i%len(fs)]
    try:
        fd=os.open(p,os.O_RDONLY); os.close(fd)
    except OSError: pass
" "$dir" "$n" ;;
  workload-exec)
    n="${2:-2000}"
    for ((i=0;i<n;i++)); do /bin/true; done ;;
  workload-connect)
    host="${2:?host required}"; port="${3:?port required}"; n="${4:-5000}"
    python3 -c "import socket,sys
h,p,n=sys.argv[1],int(sys.argv[2]),int(sys.argv[3])
for _ in range(n):
    s=socket.socket(); s.settimeout(0.2)
    try: s.connect((h,p))
    except OSError: pass
    finally: s.close()
" "$host" "$port" "$n" ;;
  *)
    grep -E '^#( |$)' "$0" | sed 's/^# \{0,1\}//'; exit 1 ;;
esac
