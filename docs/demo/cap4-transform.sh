#!/usr/bin/env bash
#
# CAPABILITY 4 — TRANSFORM BETWEEN FORMATS (one IR, many targets).
# Laptop-safe: no kernel, no root, no container.
#
# Story beat: "After I show the IR, I show it transforming between formats."
# The SAME compiled IR is lowered two ways at once:
#   (a) an AppArmor text profile          (a userspace LSM)
#   (b) BPF-LSM map entries               (an in-kernel LSM)
# Different languages, one source of truth. (The reverse direction — importing
# an existing AppArmor profile INTO the IR — is proven in cap6, the 2x2 test.)
#
# Usage:  ./docs/demo/cap4-transform.sh [events.json]
set -euo pipefail
# Resolve the (optional) events path against the caller's CWD BEFORE we cd.
if [ "${1:-}" != "" ]; then EVENTS="$(realpath -m "$1")"; fi
cd "$(dirname "$0")/../.."
EVENTS="${EVENTS:-docs/demo/example-events.json}"
[ -r "$EVENTS" ] || { echo "error: events file not found/readable: $EVENTS" >&2; exit 1; }
AA_TMP="$(mktemp --suffix=.apparmor)"
trap 'rm -f "$AA_TMP"' EXIT

if [ -x target/release/ebpf-mon ]; then BIN=(target/release/ebpf-mon); else BIN=(cargo run -q -p ebpf-mon --); fi
C='\033[1;36m'; Y='\033[1;33m'; D='\033[0;90m'; NC='\033[0m'
hr(){ echo -e "${D}------------------------------------------------------------${NC}"; }

echo -e "${C}=== One IR  ->  two enforcement languages ===${NC}"
"${BIN[@]}" --compile "$EVENTS" --emit-apparmor "$AA_TMP" >/dev/null 2>&1

hr; echo -e "${Y}(a) Lowered to AppArmor (userspace LSM, text profile):${NC}"; hr
sed 's/^/    /' "$AA_TMP"

echo
hr; echo -e "${Y}(b) Lowered to BPF-LSM (in-kernel, map entries by category):${NC}"; hr
"${BIN[@]}" --compile "$EVENTS" 2>/dev/null | sed -n '/=== COMPILE/,$p' | sed 's/^/    /'

echo
echo -e "${D}Same rules, same intent — expressed in whatever the environment gives you.${NC}"
