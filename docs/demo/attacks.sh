#!/usr/bin/env bash
#
# ATTACK / PREVENTION demo — run while ebpf-mon is ENFORCING a container.
#
# Fires a battery of "attacker" actions inside the target container and reports,
# for each, whether the eBPF LSM blocked it. Green = blocked (good under active
# enforcement). Also verifies a couple of *authorized* actions still succeed
# (no false positives).
#
# Prereqs: the container is running AND ebpf-mon is enforcing its profile, e.g.
#   sudo target/release/ebpf-mon --name <container> --enforce <profile.json>
#
# Usage:  ./docs/demo/attacks.sh <container-name> [unauthorized-ip]
set -uo pipefail

CONTAINER="${1:?usage: attacks.sh <container-name> [unauthorized-ip]}"
BAD_IP="${2:-1.1.1.1}"     # an endpoint that was NOT in the profile

G='\033[0;32m'; R='\033[0;31m'; Y='\033[1;33m'; B='\033[1;36m'; NC='\033[0m'

# blocked <label> <cmd...>   -> expect the command to FAIL (blocked = good)
blocked() {
    local label="$1"; shift
    if docker exec "$CONTAINER" sh -c "$*" >/dev/null 2>&1; then
        echo -e "  ${R}ALLOWED${NC}  $label   ${Y}(enforcement miss)${NC}"
    else
        echo -e "  ${G}BLOCKED${NC}  $label"
    fi
}

# allowed <label> <cmd...>   -> expect the command to SUCCEED (no false positive)
allowed() {
    local label="$1"; shift
    if docker exec "$CONTAINER" sh -c "$*" >/dev/null 2>&1; then
        echo -e "  ${G}OK     ${NC} $label"
    else
        echo -e "  ${R}BLOCKED${NC} $label   ${Y}(false positive — widen the profile)${NC}"
    fi
}

echo -e "${B}== Target: $CONTAINER  (unauthorized IP: $BAD_IP) ==${NC}"

echo -e "\n${B}[1] Unauthorized FILE reads (secrets) — expect BLOCKED${NC}"
blocked "read /etc/shadow"          "cat /etc/shadow"
blocked "read /etc/gshadow"         "cat /etc/gshadow"
blocked "list /root/"               "ls /root/"

echo -e "\n${B}[2] Unauthorized FILE writes (tamper/persist) — expect BLOCKED${NC}"
blocked "write /tmp/evil"           "echo pwned > /tmp/evil"
blocked "write /etc/cron.d/backdoor" "echo '* * * * * root sh' > /etc/cron.d/backdoor"

echo -e "\n${B}[3] Unauthorized EXEC (LOLBins / shells) — expect BLOCKED${NC}"
blocked "exec /bin/busybox nc"      "busybox nc -h"
blocked "exec /usr/bin/wget"        "wget --version"

echo -e "\n${B}[4] Unauthorized NETWORK egress (exfil/C2) — expect BLOCKED${NC}"
# Uses the container's own tooling; any of these connecting = enforcement miss.
blocked "connect $BAD_IP:443"       "wget -T 3 -q -O /dev/null https://$BAD_IP/ || nc -w3 $BAD_IP 443 </dev/null"

echo -e "\n${B}[5] AUTHORIZED baseline — expect OK (no false positives)${NC}"
allowed "read /etc/hostname"        "cat /etc/hostname"

echo -e "\n${B}Done.${NC} Cross-check the deny events in ebpf-mon's audit log."
