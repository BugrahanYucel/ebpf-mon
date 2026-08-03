#!/usr/bin/env python3
"""
Network noise generator for the ebpf-mon workload container.

Produces a rotating mix of outbound TCP connects and UDP sends so that the
monitor's network events keep varying (its dedup key is src_ip+dst_ip+dport).
Everything is best-effort: failures/timeouts are swallowed on purpose so the
generator never blocks the surrounding workload loop.
"""
import os
import random
import socket
import sys

# (host, port) targets. Mix of raw IPs (no DNS) and names (exercise DNS too).
TCP_TARGETS = [
    ("1.1.1.1", 443), ("1.1.1.1", 80),
    ("9.9.9.9", 443), ("8.8.8.8", 443),
    ("example.com", 80), ("example.com", 443),
    ("github.com", 443), ("debian.org", 443),
    ("cloudflare.com", 443), ("kernel.org", 443),
]

UDP_TARGETS = [
    ("8.8.8.8", 53), ("1.1.1.1", 53), ("9.9.9.9", 53),
]


def tcp_connect(host, port, timeout=3.0):
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        try:
            s.sendall(b"GET / HTTP/1.0\r\nHost: %s\r\n\r\n" % host.encode())
            s.recv(64)
        except Exception:
            pass
        s.close()
    except Exception:
        pass


def udp_send(host, port, timeout=2.0):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(os.urandom(24), (host, port))
        try:
            s.recvfrom(128)
        except Exception:
            pass
        s.close()
    except Exception:
        pass


def main():
    seed = int(sys.argv[1]) if len(sys.argv) > 1 and sys.argv[1].isdigit() else None
    rng = random.Random(seed)

    targets = list(TCP_TARGETS)
    rng.shuffle(targets)
    for host, port in targets[:4]:
        tcp_connect(host, port)

    # vary the dst *port* against a stable IP so port-based dedup keeps flowing
    for _ in range(3):
        tcp_connect("1.1.1.1", rng.randint(1024, 65500), timeout=1.0)

    for host, port in UDP_TARGETS:
        udp_send(host, port)


if __name__ == "__main__":
    main()
