#!/usr/bin/env bash
#
# CAPABILITY 2 — eBPF ENFORCEMENT (the quick taste).
# NEEDS: root + a BPF-LSM kernel + docker, with the container already enforced.
# Pre-record as backup.
#
# Story beat: right after the eBPF intro (paired with cap1-monitor). A short
# taste of default-deny: the obvious attacker moves are blocked at the kernel,
# while the container's own legit work still succeeds.
#
# Works against both demo targets:
#   vulnapp   — legit file defaults to /app/config.txt
#   secretsvc — legit file defaults to /data/orders.json; also tries secret read
#
# Prereq (in another pane, or via run-demo.sh):
#   sudo env RUST_LOG=info target/release/ebpf-mon --name <container> --enforce <profile.json>
#
# Usage:  ./docs/demo/cap2-enforce.sh <container> [legit-file]
set -uo pipefail
C="${1:?usage: cap2-enforce.sh <container> [legit-file]}"
LEGIT="${2:-/etc/hostname}"
BAD_IP="${BAD_IP:-93.184.216.34}"
G='\033[0;32m'; R='\033[0;31m'; Y='\033[1;33m'; B='\033[1;36m'; NC='\033[0m'

blocked() { # expect FAIL (blocked = good)
    local label="$1"; shift
    if docker exec "$C" sh -c "$*" >/dev/null 2>&1; then
        echo -e "  ${R}ALLOWED${NC}  $label   ${Y}(enforcement miss)${NC}"
    else
        echo -e "  ${G}BLOCKED${NC}  $label"
    fi
}
# --- preflight: this script only FIRES attacks; it does NOT load enforcement ---
docker container inspect "$C" >/dev/null 2>&1 || {
    echo -e "${R}error:${NC} container '$C' not found (docker container inspect failed)"; exit 1; }
if ! pgrep -af -- '--enforce' 2>/dev/null | grep -q -- "$C"; then
    echo -e "${Y}warning:${NC} no 'ebpf-mon --enforce' process found for '$C'."
    echo -e "         nothing is being enforced, so every attacker move below will show"
    echo -e "         ${R}ALLOWED (enforcement miss)${NC}. Start enforcement FIRST, in another pane:"
    echo -e "           ${B}sudo env RUST_LOG=info target/release/ebpf-mon --name $C --enforce <profile.json>${NC}"
    echo
fi

echo -e "${B}== enforcement taste: $C ==${NC}"
echo -e "\n${B}attacker moves — expect BLOCKED${NC}"
blocked "read secret   (cat /etc/shadow)"        "cat /etc/shadow"
# secretsvc-specific secret (harmless no-op miss on vulnapp)
if docker exec "$C" test -f /secrets/db.env 2>/dev/null; then
    blocked "read app secret (cat /secrets/db.env)" "cat /secrets/db.env"
fi
blocked "spawn a shell (exec /bin/busybox)"      "busybox true || /bin/sh -c true"
blocked "phone home    (curl un-profiled C2)"    "curl -m 3 -s http://$BAD_IP/ || wget -T3 -qO- http://$BAD_IP/"
# Even the app's OWN file, when read by a NEW process (this injected `docker exec`
# shell) rather than the app itself, is BLOCKED: default-deny permits only the
# app's own in-process access, so an attacker who lands a shell can't `cat` the
# config the app reads every request. The app's REAL in-process access is proven
# green by its HTTP endpoints in the chapter's [0]/[C] beats — not by docker exec,
# which necessarily drags in un-profiled /bin/sh + /bin/cat.
echo -e "\n${B}attacker can't even read the app's own files via an injected shell${NC}"
blocked "read $LEGIT via injected shell"         "cat $LEGIT"
