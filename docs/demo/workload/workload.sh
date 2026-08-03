#!/usr/bin/env bash
#
# ebpf-mon workload generator
# ---------------------------
# Continuously produces a rich, *non-repeating* stream of syscalls so that
# ebpf-mon captures every field it knows about:
#
#   filesystem : reads, writes, symlinks, sensitive files (is_sensitive),
#                special /proc/<pid>/... paths (path_pattern), and
#                cross-process /proc reads (is_cross_process)
#   network    : TCP + UDP to a rotating set of dst IP/port, DNS, HTTP(S)
#   process    : a rotating set of binaries and a *freshly generated* script
#                each round (new inode) exec'd with a rich argv
#
# Dedup awareness (so events keep flowing instead of collapsing):
#   fs event   key = path + inode + r_w      -> unique filenames every round
#   net event  key = src_ip + dst_ip + dport -> rotate host + random ports
#   proc event key = inode + ps_type + cgrp  -> rotate binaries / fresh script
#
# Knobs (env):
#   SLEEP_SECONDS   base delay between rounds        (default 2)
#   EXTERNAL_NET    1 = do outbound network, 0 = skip (default 1)
#
set -u

DATA_DIR="/opt/workload/data"
WORK_DIRS=("/tmp/work" "/var/tmp/work" "$DATA_DIR")
SLEEP_SECONDS="${SLEEP_SECONDS:-2}"
EXTERNAL_NET="${EXTERNAL_NET:-1}"

log() { printf '[workload] %s %s\n' "$(date -Is 2>/dev/null || date)" "$*"; }

# graceful shutdown
RUNNING=1
trap 'RUNNING=0; log "received signal, stopping..."' TERM INT

gen_token() { tr -dc 'a-f0-9' < /dev/urandom 2>/dev/null | head -c 10 || echo "$RANDOM$RANDOM"; }

jitter() {
    awk -v b="$SLEEP_SECONDS" 'BEGIN { srand(); printf "%.2f", b + (rand() * b) }' 2>/dev/null || echo "$SLEEP_SECONDS"
}

# --- filesystem: writes, reads, symlinks, copies (fresh inodes each round) ---
gen_files() {
    local d="$1"
    mkdir -p "$d" 2>/dev/null || return 0
    local f="$d/file_${TOK}.dat"

    # write (r_w = write) - random size so content differs
    head -c $(( (RANDOM % 4096) + 256 )) /dev/urandom 2>/dev/null | base64 > "$f" 2>/dev/null || true
    printf 'run=%s token=%s ts=%s\n' "$I" "$TOK" "$(date +%s%N 2>/dev/null)" >> "$f" 2>/dev/null || true

    # read back (r_w = read)
    cat "$f" > /dev/null 2>&1 || true
    wc -c "$f" > /dev/null 2>&1 || true

    # symlink + read through it (is_symlink)
    ln -sf "$f" "$d/link_${TOK}" 2>/dev/null || true
    cat "$d/link_${TOK}" > /dev/null 2>&1 || true

    # copy = read src + write a brand-new inode
    cp "$f" "$d/copy_${TOK}.dat" 2>/dev/null || true

    # prune old data so the container doesn't grow unbounded
    find "$d" -maxdepth 1 -type f -mmin +5 -delete 2>/dev/null || true
    find "$d" -maxdepth 1 -type l -delete 2>/dev/null || true
}

# --- filesystem: system + sensitive files (is_sensitive) ---
read_system() {
    local p
    for p in /etc/hostname /etc/os-release /etc/passwd /etc/hosts \
             /etc/resolv.conf /etc/nsswitch.conf /etc/group /etc/services; do
        cat "$p" > /dev/null 2>&1 || true
    done
    # sensitive credentials stores
    cat /etc/shadow  > /dev/null 2>&1 || true
    cat /etc/gshadow > /dev/null 2>&1 || true
}

# --- filesystem: special /proc paths + cross-process reads ---
read_proc() {
    local p pid
    # self (special path_pattern classifications)
    for p in cmdline environ maps status stat mounts cgroup comm; do
        cat "/proc/self/$p" > /dev/null 2>&1 || true
    done
    readlink /proc/self/exe   > /dev/null 2>&1 || true
    cat /proc/self/net/tcp    > /dev/null 2>&1 || true
    cat /proc/self/net/udp    > /dev/null 2>&1 || true
    ls  /proc/self/fd         > /dev/null 2>&1 || true

    # cross-process: pid 1 + a few random neighbours (is_cross_process)
    cat /proc/1/status  > /dev/null 2>&1 || true
    cat /proc/1/cmdline > /dev/null 2>&1 || true
    for pid in $(ls /proc 2>/dev/null | grep -E '^[0-9]+$' | shuf 2>/dev/null | head -3); do
        cat "/proc/$pid/stat"    > /dev/null 2>&1 || true
        cat "/proc/$pid/cmdline" > /dev/null 2>&1 || true
    done
}

# --- process: rotate binaries + fresh script with rich argv ---
exec_progs() {
    # a spread of real binaries, each a distinct inode, with varied args
    ls -la /tmp                                  > /dev/null 2>&1 || true
    grep -c root /etc/passwd                     > /dev/null 2>&1 || true
    find /tmp/work -maxdepth 1 -name '*.dat'     > /dev/null 2>&1 || true
    awk -v t="$TOK" 'BEGIN { print t }'          > /dev/null 2>&1 || true
    sed -n '1p' /etc/hostname                    > /dev/null 2>&1 || true
    env                                          > /dev/null 2>&1 || true
    id -u                                        > /dev/null 2>&1 || true
    uname -a                                     > /dev/null 2>&1 || true
    date +%s                                     > /dev/null 2>&1 || true
    head -c 32 /dev/urandom | base64             > /dev/null 2>&1 || true
    sha256sum /etc/hostname                      > /dev/null 2>&1 || true
    tr 'a-z' 'A-Z' <<< "$TOK"                    > /dev/null 2>&1 || true

    # a freshly generated script => new inode => guaranteed-new process event,
    # exec'd with a descriptive argv so the "arguments" field is populated
    local s="/tmp/work/gen_${TOK}.sh"
    mkdir -p /tmp/work 2>/dev/null || true
    cat > "$s" <<'EOF'
#!/bin/sh
echo "child pid=$$ ppid=$PPID args=[$*]"
EOF
    chmod +x "$s" 2>/dev/null || true
    "$s" --run "$I" --token "$TOK" --mode demo \
         --input "$DATA_DIR/file_${TOK}.dat" --verbose --retries 3 > /dev/null 2>&1 || true
    rm -f "$s" 2>/dev/null || true
}

# --- network: rotate dst host/port, mix TCP/UDP/DNS/HTTP(S) ---
do_network() {
    [ "$EXTERNAL_NET" = "1" ] || return 0

    local hosts=(example.com www.wikipedia.org github.com cloudflare.com \
                 debian.org kernel.org 1.1.1.1 8.8.8.8 9.9.9.9)
    local h="${hosts[$(( I % ${#hosts[@]} ))]}"

    # HTTP + HTTPS (TCP 80 / 443), different comm (curl/wget)
    curl -s -m 4 -o /dev/null "http://$h"   2>/dev/null || true
    curl -s -m 4 -o /dev/null "https://$h"  2>/dev/null || true
    wget -q -T 4 -t 1 -O /dev/null "https://$h" 2>/dev/null || true

    # DNS (UDP 53) with rotating names so resolvers actually get queried
    nslookup "sub${TOK}.example.com"                  > /dev/null 2>&1 || true
    getent hosts "host${TOK}.example.net"             > /dev/null 2>&1 || true
    command -v dig >/dev/null 2>&1 && \
        dig +short +time=2 +tries=1 "r${TOK}.example.org" > /dev/null 2>&1 || true

    # raw TCP / UDP with rotating dst IP + random dst ports (python helper)
    python3 /opt/workload/netgen.py "$I" 2>/dev/null || true
}

log "starting workload (SLEEP_SECONDS=$SLEEP_SECONDS EXTERNAL_NET=$EXTERNAL_NET)"
mkdir -p "${WORK_DIRS[@]}" 2>/dev/null || true

I=0
while [ "$RUNNING" = "1" ]; do
    I=$(( I + 1 ))
    TOK="$(gen_token)"

    for d in "${WORK_DIRS[@]}"; do
        gen_files "$d"
    done
    read_system
    read_proc
    exec_progs
    do_network

    log "iteration=$I token=$TOK"
    sleep "$(jitter)"
done

log "stopped."
