#!/usr/bin/env python3
"""pcap 하나의 HTTP 요청 리듬을 요약한다(분석만, 네트워크 없음).

사용: python3 -I tests/rhythm.py <pcap> [--src <출발지 IP>] [--burst 0.3] [--json 출력.json]
링크 형식: Ethernet(1), Linux SLL2(276).
뽑는 것: 요청 간 간격 분포, 몰아치기(간격 < burst 초) 구조, UA별 간격, 동시에 열린 TCP 연결 수.
"""
import argparse, json, re, statistics, struct, sys
from collections import Counter, defaultdict

BINS = [(0, 0.05), (0.05, 0.3), (0.3, 1), (1, 3), (3, 10), (10, 30), (30, 1e9)]


def packets(path):
    f = open(path, "rb")
    gh = f.read(24)
    lt = struct.unpack("<I", gh[20:24])[0]
    off = {1: 14, 276: 20}[lt]
    while True:
        h = f.read(16)
        if len(h) < 16:
            return
        ts, us, il, _ = struct.unpack("<IIII", h)
        d = f.read(il)
        ip = d[off:]
        if len(ip) < 20 or ip[0] >> 4 != 4 or ip[9] != 6:
            continue
        ihl = (ip[0] & 15) * 4
        tcp = ip[ihl:]
        src = ".".join(map(str, ip[12:16])); dst = ".".join(map(str, ip[16:20]))
        sp, dp = struct.unpack(">HH", tcp[0:4])
        flags = tcp[13]
        yield ts + us / 1e6, src, sp, dst, dp, flags, tcp[(tcp[12] >> 4) * 4:]


def q(xs, p):
    xs = sorted(xs)
    return round(xs[min(len(xs) - 1, int(p * len(xs)))], 3) if xs else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap"); ap.add_argument("--src"); ap.add_argument("--burst", type=float, default=0.3); ap.add_argument("--json")
    a = ap.parse_args()
    reqs, conns, open_now, max_open = [], {}, set(), 0
    for ts, src, sp, dst, dp, flags, pl in packets(a.pcap):
        key = (src, sp, dst, dp)
        if flags & 0x02 and not flags & 0x10 and (not a.src or src == a.src):   # SYN
            open_now.add(key); max_open = max(max_open, len(open_now))
        if flags & 0x05:                                                         # FIN/RST
            open_now.discard(key); open_now.discard((dst, dp, src, sp))
        m = re.match(rb"(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS) (\S+) HTTP/1\.[01]\r\n", pl)
        if m and (not a.src or src == a.src):
            ua = re.search(rb"\r\n[Uu]ser-[Aa]gent: ([^\r\n]*)", pl)
            reqs.append((ts, f"{src}:{sp}", (ua.group(1).decode(errors="ignore") if ua else "-")[:40], m.group(1).decode(), m.group(2).decode(errors="ignore")[:80]))
    reqs.sort()
    gaps = [round(b[0] - a_[0], 4) for a_, b in zip(reqs, reqs[1:])]
    bins = {f"{lo}-{hi if hi < 1e9 else 'inf'}s": sum(1 for g in gaps if lo <= g < hi) for lo, hi in BINS}
    bursts, cur = [], 1
    for g in gaps:
        if g < a.burst: cur += 1
        else: bursts.append(cur); cur = 1
    if reqs: bursts.append(cur)
    between = [g for g in gaps if g >= a.burst]
    per_ua = defaultdict(list)
    for r in reqs: per_ua[r[2]].append(r[0])
    ua_stats = {u: {"n": len(t), "median_gap_s": q([y - x for x, y in zip(t, t[1:])], 0.5)} for u, t in per_ua.items()}
    out = {
        "pcap": a.pcap, "requests": len(reqs), "duration_s": round(reqs[-1][0] - reqs[0][0], 2) if reqs else 0,
        "gap_bins": bins,
        "share_gap_lt_burst": round(sum(1 for g in gaps if g < a.burst) / len(gaps), 3) if gaps else None,
        "bursts": {"count": len(bursts), "mean_size": round(statistics.mean(bursts), 2) if bursts else 0, "max_size": max(bursts) if bursts else 0,
                   "size_hist": dict(sorted(Counter(min(b, 10) for b in bursts).items()))},
        "between_burst_gap_s": {"p10": q(between, .1), "median": q(between, .5), "p90": q(between, .9)},
        "max_concurrent_tcp": max_open, "user_agents": ua_stats,
    }
    print(json.dumps(out, ensure_ascii=False, indent=1))
    if a.json:
        json.dump(out, open(a.json, "w"), ensure_ascii=False, indent=1)


if __name__ == "__main__":
    main()
