#!/usr/bin/env python3
"""출발지별 ARTEX 의심 점수(가중 신호 조합) 기준 구현. pcap을 직접 읽는다(분석만, 네트워크 없음).

로그 분석(Suricata eve의 HTTP 헤더 기록, Zeek 등)으로 옮길 때의 논리를 그대로 담는다.
신호와 점수(2026-11-21 초안, 실험실 실측 근거: docs/lab-mock-2026-11-21.md):
  ua      +5  ARTEX·포크 고유 UA(norma/, spa-api-recon, artex-, (ARTEX), 포크 이름)
  spoof   +4  브라우저 UA인데 헤더 구성이 Go 기본 또는 Python urllib 기본과 정확히 같음(9278394·95)
  login   +2  로그인 경로 POST가 30초 안에 7건 이상(9278390)
  mix     +2  30초 창 안에 비브라우저 클라이언트 종류 2개(3개 이상이면 +3)
  burst   +1  요청 10건 이상이고 요청 간격의 절반 이상이 0.3초 미만
판정: 5점 이상 "ARTEX 가능성 높음", 3~4점 "조사", 그 아래 무시.
--keep-kinds curl: 모델이 ARTEX 도구 대신 curl만 쓴 경우 흉내(Theori 실측에서 관찰된 행태).
--simulate-fork-ua: ARTEX 도구 UA를 Chrome UA로 바꿔 읽는다(UA만 바꾼 포크 흉내, 헤더 순서는 그대로).
사용: python3 -I tests/score_sources.py <pcap> [--simulate-fork-ua]
"""
import argparse, json, os, re, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from rhythm import packets  # noqa: E402
from streams import shape  # noqa: E402

CHROME = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
ARTEX_UA = re.compile(r"^(?:norma/|artex-|Mozilla/5\.0 \(spa-api-recon)|\(ARTEX\)|ARTEX-|scopeweaver|antifox|artifex|wsartex|prtseek|YCode-recon", re.I)
LOGIN = re.compile(r"(?:log_?in|sign_?in|auth)", re.I)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap"); ap.add_argument("--simulate-fork-ua", action="store_true")
    ap.add_argument("--keep-kinds", help="이 클라이언트 종류만 남김(쉼표). 예: curl = 모델이 ARTEX 도구 없이 curl만 쓴 경우 흉내")
    a = ap.parse_args()
    reqs = []
    for ts, src, sp, dst, dp, flags, pl in packets(a.pcap):
        m = re.match(rb"(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS) (\S+) HTTP/1\.[01]\r\n(.*?)\r\n\r\n", pl, re.S)
        if not m:
            continue
        hs = [l.split(b":", 1) for l in m.group(3).split(b"\r\n") if b":" in l]
        names = [k.decode() for k, _ in hs]
        vals = {k.decode().lower(): v.decode(errors="ignore").strip() for k, v in hs}
        ua = vals.get("user-agent", "")
        if a.simulate_fork_ua and ARTEX_UA.search(ua):
            ua = vals["user-agent"] = CHROME
        reqs.append({"ts": ts, "src": src, "method": m.group(1).decode(), "uri": m.group(2).decode(errors="ignore"),
                     "ua": ua, "kind": shape(names, vals)})
    if a.keep_kinds:
        keep = set(a.keep_kinds.split(","))
        reqs = [r for r in reqs if r["kind"] in keep]
    reqs.sort(key=lambda r: r["ts"])
    out = {}
    for src in sorted({r["src"] for r in reqs}):
        rs = [r for r in reqs if r["src"] == src]
        sig = {}
        if any(ARTEX_UA.search(r["ua"]) for r in rs):
            sig["ua"] = 5
        if any(r["ua"].startswith("Mozilla/5.0") and "spa-api-recon" not in r["ua"] and r["kind"] in ("go-default", "py-urllib") for r in rs):
            sig["spoof"] = 4
        posts = [r["ts"] for r in rs if r["method"] == "POST" and LOGIN.search(r["uri"])]
        if any(sum(1 for t in posts if 0 <= t - t0 <= 30) >= 7 for t0 in posts):
            sig["login"] = 2
        mix, j = 0, 0
        for i in range(len(rs)):
            while rs[i]["ts"] - rs[j]["ts"] > 30: j += 1
            mix = max(mix, len({r["kind"] for r in rs[j:i + 1] if r["kind"] != "browser"}))
        if mix >= 3: sig["mix"] = 3
        elif mix == 2: sig["mix"] = 2
        gaps = [b["ts"] - x["ts"] for x, b in zip(rs, rs[1:])]
        if len(rs) >= 10 and sum(1 for g in gaps if g < 0.3) / len(gaps) >= 0.5:
            sig["burst"] = 1
        score = sum(sig.values())
        out[src] = {"requests": len(rs), "score": score, "signals": sig,
                    "verdict": "ARTEX 가능성 높음" if score >= 5 else "조사" if score >= 3 else "무시"}
    print(json.dumps(out, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
