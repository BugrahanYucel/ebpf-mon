#!/usr/bin/env bash
#
# CAPABILITY 6 — CROSS-FORMAT ENFORCEMENT EQUIVALENCE (the concrete 2x2).
# Runs in userspace: NO kernel, NO root, NO container.  DO NOT run with sudo
# (cargo lives in your user's ~/.cargo/bin and is not on root's PATH).
#
# Story beat: the climax of the compiler argument, shown — not asserted. The
# SAME policy is expressed in TWO source formats (eBPF monitor events + a
# hand-written AppArmor profile); both compile to the SAME IR; that ONE IR is
# lowered to TWO enforcement formats (AppArmor text + BPF-LSM map plan); and the
# SAME battery of operations gets identical verdicts under both formats — plus
# the three places the formats deliberately diverge.
#
# Usage:  ./docs/demo/cap6-2x2.sh          (no sudo)
set -euo pipefail
cd "$(dirname "$0")/../.."

# The example reuses the real frontends/passes/backends (not a mock). Prefer a
# prebuilt binary so this also works under sudo and needs no compile on stage.
BIN="target/debug/examples/cross_format"
if [ ! -x "$BIN" ]; then
  if command -v cargo >/dev/null 2>&1; then
    echo ">>> building the cross_format example (one-time)..." >&2
    cargo build -q -p ebpf-mon-common --features user --example cross_format
  else
    echo "error: cargo not found and no prebuilt $BIN." >&2
    echo "  You probably ran this with sudo — don't. This demo needs no root." >&2
    echo "  Or prebuild once:  cargo build -p ebpf-mon-common --features user --example cross_format" >&2
    exit 1
  fi
fi
"$BIN"
