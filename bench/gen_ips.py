#!/usr/bin/env python3
"""Sinh N địa chỉ IPv4 ngẫu nhiên, không trùng, để làm rule "không khớp" cho Đo 2.

Seed cố định => mọi lần chạy (và mọi cấu hình) nhận cùng một danh sách rule (research R9).
KHỐI B10 (benchmark) — docs/ARCHITECTURE.md §4.
Loại trừ 10.10.0.0/16 (lab) và các dải đặc biệt để rule không bao giờ khớp traffic của lab.

    python3 bench/gen_ips.py 999 > rules.txt
"""
import ipaddress
import random
import sys

EXCLUDED = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.10.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/3",
)]


def gen(n: int, seed: int = 42) -> list[str]:
    rng = random.Random(seed)
    seen: set[int] = set()
    out: list[str] = []
    while len(out) < n:
        v = rng.getrandbits(32)
        ip = ipaddress.IPv4Address(v)
        if v in seen or any(ip in net for net in EXCLUDED):
            continue
        seen.add(v)
        out.append(str(ip))
    return out


if __name__ == "__main__":
    if len(sys.argv) not in (2, 3):
        sys.exit("usage: gen_ips.py N [seed]")
    n = int(sys.argv[1])
    seed = int(sys.argv[2]) if len(sys.argv) == 3 else 42
    print("\n".join(gen(n, seed)))
