#!/usr/bin/env python3
"""pcap에서 출발지별 '작업 줄기' 구조를 요약한다(분석만, 네트워크 없음).

요청마다 헤더 모양으로 클라이언트 종류를 붙인다(UA와 무관: go-default, py-urllib, curl, wget, browser, other).
출발지마다 뽑는 것:
- 종류별 요청 수, 처음·마지막 시각
- 클라이언트 혼합: 길이 W초 창 안에서 동시에 보이는 비브라우저 종류 수의 최댓값
- 교대: 한 종류가 마지막 요청을 낸 뒤 L초 안에 새 종류(처음 등장)가 시작한 횟수와 그 간격
사용: python3 -I tests/streams.py <pcap> [--window 30] [--handoff 30]
"""
import argparse, json, re, sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from rhythm import packets  # noqa: E402


def shape(names, vals):
    n = [x.lower() for x in names]
    ae = vals.get("accept-encoding", "")
    if n == ["host", "user-agent", "accept-encoding"] and ae == "gzip":
        return "go-default"
    if n == ["accept-encoding", "host", "user-agent", "connection"] and ae == "identity":
        return "py-urllib"
    if n[:3] == ["host", "user-agent", "accept"] and vals.get("accept") == "*/*" and "connection" not in n:
        return "curl"
    if n[:2] == ["host", "user-agent"] and "connection" in n and vals.get("connection", "").lower() == "keep-alive" and ae == "identity":
        return "wget"
    if "connection" in n and ("referer" in n or "upgrade-insecure-requests" in n or "origin" in n or "sec-websocket-key" in n):
        return "browser"
    return "other"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap"); ap.add_argument("--window", type=float, default=30); ap.add_argument("--handoff", type=float, default=30)
    a = ap.parse_args()
    reqs = []
    for ts, src, sp, dst, dp, flags, pl in packets(a.pcap):
        m = re.match(rb"(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS) (\S+) HTTP/1\.[01]\r\n(.*?)\r\n\r\n", pl, re.S)
        if not m:
            continue
        hs = [l.split(b":", 1) for l in m.group(3).split(b"\r\n") if b":" in l]
        names = [k.decode() for k, _ in hs]
        vals = {k.decode().lower(): v.decode(errors="ignore").strip() for k, v in hs}
        reqs.append((ts, src, shape(names, vals)))
    reqs.sort()
    out = {}
    for src in sorted({r[1] for r in reqs}):
        rs = [r for r in reqs if r[1] == src]
        kinds = {}
        for ts, _, k in rs:
            d = kinds.setdefault(k, {"n": 0, "first": ts, "last": ts}); d["n"] += 1; d["last"] = ts
        t0 = rs[0][0]
        mix, j = 0, 0
        for i in range(len(rs)):
            while rs[i][0] - rs[j][0] > a.window: j += 1
            mix = max(mix, len({k for _, _, k in rs[j:i + 1] if k != "browser"}))
        handoffs = []
        order = sorted(kinds.items(), key=lambda kv: kv[1]["first"])
        for k, d in order[1:]:
            ended = [kd["last"] for kk, kd in kinds.items() if kk != k and kd["last"] <= d["first"] and d["first"] - kd["last"] <= a.handoff]
            if ended:
                handoffs.append({"new": k, "gap_s": round(d["first"] - max(ended), 2)})
        out[src] = {"requests": len(rs), "duration_s": round(rs[-1][0] - t0, 1),
                    "kinds": {k: {"n": d["n"], "first_s": round(d["first"] - t0, 1), "last_s": round(d["last"] - t0, 1)} for k, d in order},
                    f"max_nonbrowser_kinds_in_{int(a.window)}s": mix, "handoffs": handoffs}
    print(json.dumps(out, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
