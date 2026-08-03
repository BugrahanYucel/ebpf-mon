#!/usr/bin/env bash
#
# ftrace_bench.sh — measure enforcement-hook latency with ftrace, for comparing
# OPTIMIZED vs UNOPTIMIZED policies (ebpf-mon --enforce  vs  --enforce --no-optimize).
#
# Standalone: touches nothing in the project. Uses the kernel ftrace *function
# profiler* (/sys/kernel/tracing/function_profile_enabled + trace_stat) to record,
# per kernel function, the hit count and average time spent. We filter to the three
# LSM enforcement hooks so overhead stays low:
#
#   security_file_open       <- lsm/file_open       (enforce_file_open)
#   security_bprm_check      <- lsm/bprm_check_...  (enforce_bprm_check)
#   security_socket_connect  <- lsm/socket_connect  (enforce_socket_connect)
#
# These wrappers include your BPF program's run time, so the delta between an
# optimized and an unoptimized policy (fewer rules -> smaller maps, shorter Tier-3
# prefix scan) shows up here. For BPF-program-only cost, use bpf_bench.sh; the two
# are complementary (hook wall-time vs isolated prog time).
#
# NOTE ON ATTRIBUTION: security_* wrappers also run any other active LSMs
# (SELinux/AppArmor). That baseline is constant across the A/B, so the
# optimized-vs-unoptimized *delta* still isolates the effect of policy size.
#
# Requires: sudo, python3, and a kernel with ftrace function profiler
# (CONFIG_FUNCTION_PROFILER + CONFIG_FUNCTION_GRAPH_TRACER).
#
# ── A/B protocol ─────────────────────────────────────────────────────────────
#   1) Terminal A:  sudo ./ebpf-mon --enforce --container <ctr>            # optimized
#   2) Terminal B:  sudo ./ftrace_bench.sh measure optimized "<workload cmd>"
#   3) Stop ebpf-mon, restart:  sudo ./ebpf-mon --enforce --no-optimize --container <ctr>
#   4) Terminal B:  sudo ./ftrace_bench.sh measure unoptimized "<workload cmd>"
#   5)              sudo ./ftrace_bench.sh compare optimized unoptimized
#
# Use the SAME deterministic workload for both runs, e.g.
#   "docker exec <ctr> pgbench -c 16 -j 4 -T 60 -U postgres postgres"
#
# ── Usage ────────────────────────────────────────────────────────────────────
#   sudo ./ftrace_bench.sh check                       # verify env + traceable funcs
#   sudo ./ftrace_bench.sh measure <label> "<cmd>"     # profile around a command
#   sudo ./ftrace_bench.sh measure <label> --window N  # profile a manual N-second window
#   sudo ./ftrace_bench.sh compare <labelA> <labelB>   # diff two saved runs
#
# Extra functions can be added via env:  FUNCS="foo bar" sudo ./ftrace_bench.sh ...
set -euo pipefail

# Default target functions (the enforcement-hook wrappers). Override/extend with $FUNCS.
DEFAULT_FUNCS=(security_file_open security_bprm_check security_socket_connect)
read -r -a EXTRA_FUNCS <<< "${FUNCS:-}"
TARGETS=("${DEFAULT_FUNCS[@]}" "${EXTRA_FUNCS[@]}")

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_DIR="${RESULTS_DIR:-$SCRIPT_DIR/ftrace-results}"

# Locate tracefs.
find_tracefs() {
  for d in /sys/kernel/tracing /sys/kernel/debug/tracing; do
    [[ -f "$d/function_profile_enabled" ]] && { echo "$d"; return 0; }
  done
  return 1
}

need_root() { [[ "$(id -u)" -eq 0 ]] || { echo "error: run as root (sudo)" >&2; exit 1; }; }

# Functions actually present in this kernel's available_filter_functions.
available_targets() {
  local tp="$1"; shift
  local avail="$tp/available_filter_functions"
  for fn in "${TARGETS[@]}"; do
    if grep -qxE "$fn(\s.*)?" "$avail" 2>/dev/null || grep -qw "$fn" "$avail" 2>/dev/null; then
      echo "$fn"
    fi
  done
}

cmd_check() {
  need_root
  local tp; tp="$(find_tracefs)" || { echo "error: tracefs with function_profile_enabled not found (need CONFIG_FUNCTION_PROFILER)" >&2; exit 1; }
  echo "tracefs:        $tp"
  echo "results dir:    $RESULTS_DIR"
  echo "target funcs:   ${TARGETS[*]}"
  echo
  echo "traceable on this kernel:"
  local found; found="$(available_targets "$tp")"
  if [[ -z "$found" ]]; then
    echo "  (none — none of the target symbols are in available_filter_functions)"
    echo "  Are the enforcement hooks compiled in? Try: grep security_file_open $tp/available_filter_functions"
    exit 1
  fi
  while read -r f; do echo "  + $f"; done <<< "$found"
}

# Set the ftrace filter to the given functions (one per line already).
apply_filter() {
  local tp="$1" funcs="$2"
  : > "$tp/set_ftrace_filter"
  while read -r f; do [[ -n "$f" ]] && echo "$f" >> "$tp/set_ftrace_filter"; done <<< "$funcs"
}

cmd_measure() {
  need_root
  local label="${1:?label required (e.g. optimized)}"; shift
  local tp; tp="$(find_tracefs)" || { echo "error: tracefs not found" >&2; exit 1; }

  local funcs; funcs="$(available_targets "$tp")"
  [[ -n "$funcs" ]] || { echo "error: no target functions traceable; run 'check'" >&2; exit 1; }

  mkdir -p "$RESULTS_DIR"
  local out="$RESULTS_DIR/$label.txt"

  # Reset + arm the profiler on just our functions.
  echo 0 > "$tp/function_profile_enabled"
  apply_filter "$tp" "$funcs"
  echo 1 > "$tp/function_profile_enabled"   # toggling 0->1 clears prior histogram

  local wall_start wall_end
  wall_start=$(date +%s.%N)
  if [[ "${1:-}" == "--window" ]]; then
    local secs="${2:?seconds required}"
    echo "profiling for ${secs}s — drive your workload now..."
    sleep "$secs"
  elif [[ -n "${1:-}" ]]; then
    echo "profiling around: $*"
    bash -c "$*" || echo "(workload command exited non-zero; stats still captured)"
  else
    echo "profiling until you press Enter — drive your workload now..."
    read -r _
  fi
  wall_end=$(date +%s.%N)

  echo 0 > "$tp/function_profile_enabled"

  # Aggregate per-CPU trace_stat/function* into one table.
  python3 - "$label" "$wall_start" "$wall_end" "$tp" "${funcs//$'\n'/ }" <<'PY' | tee "$out"
import sys, glob, os
label, w0, w1, tp = sys.argv[1], float(sys.argv[2]), float(sys.argv[3]), sys.argv[4]
wanted = set(sys.argv[5].split())

# Sum hits and total time (usec) across all per-CPU stat files.
agg = {}  # fn -> [hits, time_us]
for path in glob.glob(os.path.join(tp, "trace_stat", "function*")):
    with open(path) as fh:
        for line in fh:
            parts = line.split()
            if len(parts) < 3 or not parts[1].isdigit():
                continue
            fn = parts[0]
            if fn not in wanted:
                continue
            hits = int(parts[1])
            # Time column looks like "6789.012" possibly followed by "us".
            try:
                t_us = float(parts[2])
            except ValueError:
                continue
            a = agg.setdefault(fn, [0, 0.0])
            a[0] += hits
            a[1] += t_us

print(f"# ftrace hook latency — label='{label}'  wall={w1-w0:.2f}s")
print(f"{'hook':<26}{'hits':>12}{'total_us':>16}{'avg_ns/call':>16}")
print("-" * 70)
if not agg:
    print("(no hits recorded — was the workload driving the enforced container?)")
for fn in sorted(agg, key=lambda k: (agg[k][1]/agg[k][0]) if agg[k][0] else 0, reverse=True):
    hits, t_us = agg[fn]
    avg_ns = (t_us / hits * 1000.0) if hits else 0.0
    print(f"{fn:<26}{hits:>12}{t_us:>16.3f}{avg_ns:>16.1f}")
PY

  # Cleanup: clear filter so we don't leave the profiler armed.
  : > "$tp/set_ftrace_filter"
  echo
  echo "saved: $out"
}

cmd_compare() {
  local a="${1:?labelA required}" b="${2:?labelB required}"
  local fa="$RESULTS_DIR/$a.txt" fb="$RESULTS_DIR/$b.txt"
  [[ -f "$fa" ]] || { echo "error: no results for '$a' ($fa)" >&2; exit 1; }
  [[ -f "$fb" ]] || { echo "error: no results for '$b' ($fb)" >&2; exit 1; }
  python3 - "$a" "$fa" "$b" "$fb" <<'PY'
import sys
la, fa, lb, fb = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]

def parse(path):
    rows = {}
    with open(path) as fh:
        for line in fh:
            p = line.split()
            if len(p) == 4 and p[0] not in ("hook",) and not p[0].startswith(("#", "-")):
                try:
                    rows[p[0]] = (int(p[1]), float(p[3]))  # hits, avg_ns
                except ValueError:
                    pass
    return rows

ra, rb = parse(fa), parse(fb)
print(f"{'hook':<26}{la+' ns':>14}{lb+' ns':>14}{'delta':>12}{'delta%':>10}")
print("-" * 76)
for fn in sorted(set(ra) | set(rb)):
    va = ra.get(fn, (0, 0.0))[1]
    vb = rb.get(fn, (0, 0.0))[1]
    d = vb - va
    pct = (d / va * 100.0) if va else float('nan')
    print(f"{fn:<26}{va:>14.1f}{vb:>14.1f}{d:>12.1f}{pct:>9.1f}%")
print()
print(f"(negative delta = '{lb}' is faster than '{la}')")
PY
}

case "${1:-}" in
  check)   cmd_check ;;
  measure) shift; cmd_measure "$@" ;;
  compare) shift; cmd_compare "$@" ;;
  *) grep -E '^#( |$)' "$0" | sed 's/^# \{0,1\}//'; exit 1 ;;
esac
