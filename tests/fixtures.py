"""anti-artex 탐지 룰 회귀 시험용 합성 pcap 생성기. 파이썬 표준 라이브러리만 쓴다.

- 케이스마다 TCP 세션 하나(handshake → HTTP 요청 → 200 응답 → FIN). 출발 포트로 케이스를 구분한다.
- 주소는 문서용 대역(192.0.2.10 → 198.51.100.20:80)만 쓴다. 네트워크로 아무것도 보내지 않는다.
- source-shape 케이스는 ARTEX v0.3.15 소스(원본 v0.3.15 백업)·Norma SDK를 텍스트로 읽어 요청 모양만 옮긴 것이다.

expect: True = 탐지해야 함, False = 탐지하면 안 됨(오탐 측정), None = 참고용.

사용: python3 tests/fixtures.py OUT.pcap OUT-index.json
"""
import json
import random
import struct
import sys

random.seed(278301)

BROWSER = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"


def req(method, path, ua, headers=(), body="", host="app.example.test"):
    r = f"{method} {path} HTTP/1.1\r\nHost: {host}\r\n"
    if ua is not None:
        r += f"User-Agent: {ua}\r\n"
    r += "Accept: */*\r\n"
    for k, v in headers:
        r += f"{k}: {v}\r\n"
    if body:
        r += f"Content-Length: {len(body.encode())}\r\n"
    return (r + "\r\n" + body).encode()


JSON = [("Content-Type", "application/json")]

# (id, 묶음, expect, 설명, 요청 바이트)
CASES = [
    ("E-enrich", "source-shape", True, "enrich/enrich.go:233 자산 보강 단발 GET, UA artex-enrich/1.0, Connection: close",
     req("GET", "/", "artex-enrich/1.0", [("Connection", "close")])),
    ("N-webfetch", "source-shape", True, "Norma tool/webfetch.go WebFetch UA norma/0.4",
     req("GET", "/docs/api", "norma/0.4")),
    ("A-spider", "source-shape", True, "skills/api-recon/scripts/spider_mpa.py UA",
     req("GET", "/products?page=2", "Mozilla/5.0 (spa-api-recon spider)")),
    ("A-static", "source-shape", True, "skills/api-recon/scripts/harvest_static.py UA",
     req("GET", "/static/js/main.3f2a.js", "Mozilla/5.0 (spa-api-recon)")),
    ("U-selfupdate", "source-shape", True, "selfupdate/github.go 자가 업데이트(운영자 쪽 egress, 정책 룰)",
     req("GET", "/repos/Autumn-27/ARTEX/releases/latest", "artex-selfupdate", host="api.github.com")),
    ("B-backdoor-login", "report-shape", True, "백도어 이미지 tomicdd/artex 로그인 captcha '!' 접두 명령(제3자 포렌식 보고 모양)",
     req("POST", "/api/auth/login", BROWSER, JSON, json.dumps({"username": "admin", "password": "x", "captcha": "!id"}))),
    ("B-backdoor-login-sp", "report-shape", True, "같은 모양, JSON 공백 변형",
     req("POST", "/api/auth/login", BROWSER, JSON, '{"username":"admin", "password":"x", "captcha" : "!uname -a"}')),
    ("X-browser", "benign", False, "일반 브라우저 GET", req("GET", "/", BROWSER)),
    ("X-curl", "benign", False, "curl GET", req("GET", "/health", "curl/8.7.1")),
    ("X-normalizer", "benign", False, "norma로 시작하지만 다른 UA(normalizer/2.0)", req("GET", "/", "normalizer/2.0")),
    ("X-norma-mid", "benign", False, "UA 가운데에 norma/ 문자열", req("GET", "/", "Mozilla/5.0 (X11; Linux) norma/1.0 compatible")),
    ("X-artex-in-query", "benign", False, "UA는 브라우저, 쿼리에 artex-enrich/ 문자열", req("GET", "/search?q=artex-enrich/1.0", BROWSER)),
    ("X-spa-word", "benign", False, "괄호 없는 spa-api-recon 언급 UA", req("GET", "/", "spa-api-recon-docs-bot/1.0")),
    ("X-login-captcha", "benign", False, "정상 로그인 captcha 값", req("POST", "/api/auth/login", BROWSER, JSON, json.dumps({"username": "u", "password": "p", "captcha": "a7k2"}))),
    ("X-login-nocaptcha", "benign", False, "captcha 없는 로그인", req("POST", "/api/auth/login", BROWSER, JSON, json.dumps({"username": "u", "password": "!startswithbang"}))),
    ("X-other-login-bang", "benign", False, "다른 경로의 captcha '!' 값", req("POST", "/login", BROWSER, JSON, json.dumps({"captcha": "!id"}))),
    ("X-github-ui", "benign", False, "GitHub API 일반 UA", req("GET", "/repos/x/y/releases/latest", "Go-http-client/1.1", host="api.github.com")),
    ("F-artifex-enrich", "fork-shape", True, "포크 16 enrich UA", req("GET", "/", "artifex-enrich/1.0")),
    ("F-antifox-enrich", "fork-shape", True, "AntiFox 포크 enrich UA", req("GET", "/", "antifox-enrich/1.0")),
    ("F-wsartex-enrich", "fork-shape", True, "포크 20 enrich UA", req("GET", "/", "wsartex-enrich/1.0")),
    ("F-prtseek-enrich", "fork-shape", True, "prtseek enrich UA", req("GET", "/", "prtseek-enrich/1.0")),
    ("F-artex-http-shell", "fork-shape", True, "포크 05·focus-agent http_shell UA", req("GET", "/admin", "Mozilla/5.0 (ARTEX)")),
    ("F-artex-nuclei-fp", "fork-shape", True, "포크 19 Nuclei 지문 UA", req("GET", "/", "Mozilla/5.0 (compatible; ARTEX-Nuclei-Fingerprint/1.0)")),
    ("F-artex-subfinder", "fork-shape", True, "포크 19 Subfinder MCP UA", req("GET", "/", "Mozilla/5.0 (compatible; ARTEX-Subfinder-MCP/1.0)")),
    ("F-ycode-recon", "fork-shape", True, "ycode-auto-pentest recon UA", req("GET", "/", "YCode-recon/0.3")),
    ("F-prtseek-obs", "fork-shape", True, "prtseek HTTP 관찰 UA", req("GET", "/", "prtseek/1.2 HTTP observation")),
    ("F-artifex-ct", "fork-shape", True, "ARTIFEX 인증서 하위 도메인 UA", req("GET", "/", "Mozilla/5.0 (X11; Linux x86_64) Artifex-ct-subs")),
    ("F-scopeweaver-upd", "fork-shape", True, "ScopeWeaver 포크 자가 업데이트(POLICY)", req("GET", "/repos/x/scopeweaver/releases/latest", "scopeweaver-selfupdate", host="api.github.com")),
    ("F-pojun-upd", "fork-shape", True, "포크 30 자가 업데이트(POLICY)", req("GET", "/repos/x/Pojun/releases/latest", "pojun-selfupdate", host="api.github.com")),
    ("F-artex-update-check", "fork-shape", True, "포크 01 업데이트 확인(POLICY)", req("GET", "/repos/x/ARTEX/releases/latest", "artex-update-check", host="api.github.com")),
    ("X-enrich-generic", "benign", False, "다른 제품의 -enrich UA", req("GET", "/", "geo-enrich/2.3")),
    ("X-artexpo", "benign", False, "ARTEX 비슷한 단어가 든 UA", req("GET", "/", "Mozilla/5.0 (compatible; ArtExpoBot/1.0; +https://artexpo.example)")),
    ("X-prtseek-word", "benign", False, "prtseek 블로그 방문 브라우저(쿼리)", req("GET", "/?ref=prtseek", BROWSER)),
]


def _csum(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def _ip(ip):
    return bytes(int(x) for x in ip.split("."))


def _pkt(src, dst, sport, dport, seq, ack, flags, payload=b""):
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0)
    pseudo = _ip(src) + _ip(dst) + struct.pack("!BBH", 0, 6, 20 + len(payload))
    tcp = tcp[:16] + struct.pack("!H", _csum(pseudo + tcp + payload)) + tcp[18:]
    iph = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40 + len(payload), random.getrandbits(16), 0x4000, 64, 6, 0, _ip(src), _ip(dst))
    iph = iph[:10] + struct.pack("!H", _csum(iph)) + iph[12:]
    return b"\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01\x08\x00" + iph + tcp + payload


def main(out_pcap, out_index, extra=True):
    random.seed(20261121)  # IP ID를 고정해 실행마다 같은 pcap을 만든다(Suricata detection_filter 결과가 흔들리지 않게)
    srv = "198.51.100.20"
    t = 1763424000.0
    frames, index = [], {}
    resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nok"
    cases = list(CASES)
    if extra:
        import os
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from shape_fixtures import CASES as SHAPE_CASES  # 요청 모양(9278394·95) 케이스
        cases += SHAPE_CASES
    # 로그인 연속(9278390): 다른 출발지에서 30초 안 로그인 POST 9건 → 7번째부터 탐지. 사람 모양은 3건.
    burst = "192.0.2.20"
    for k in (range(1, 10) if extra else ()):
        body = json.dumps({"email": "admin@example.test", "password": f"guess{k}"})
        cases.append((f"L-burst-{k}", "behavior", True if k >= 7 else None, f"로그인 POST 연속 {k}번째(실측 모양: 워커 curl)",
                      req("POST", "/rest/user/login", "curl/7.88.1", JSON, body), burst))
    for k in (range(1, 4) if extra else ()):
        body = json.dumps({"email": "user@example.test", "password": f"typo{k}"})
        cases.append((f"L-human-{k}", "benign", False, f"사람 로그인 {k}번째(틀리고 다시)", req("POST", "/rest/user/login", BROWSER, JSON, body), "192.0.2.30"))
    for n, case in enumerate(cases):
        cid, group, expect, desc, request = case[:5]
        cli = case[5] if len(case) > 5 else "192.0.2.10"
        sport = 20000 + n
        index[sport] = {"id": cid, "group": group, "expect": expect, "desc": desc}
        cs, ss, q = 1000, 5000, len(request)
        for s in [
            (cli, srv, sport, 80, cs, 0, 0x02, b""),
            (srv, cli, 80, sport, ss, cs + 1, 0x12, b""),
            (cli, srv, sport, 80, cs + 1, ss + 1, 0x10, b""),
            (cli, srv, sport, 80, cs + 1, ss + 1, 0x18, request),
            (srv, cli, 80, sport, ss + 1, cs + 1 + q, 0x10, b""),
            (srv, cli, 80, sport, ss + 1, cs + 1 + q, 0x18, resp),
            (cli, srv, sport, 80, cs + 1 + q, ss + 1 + len(resp), 0x10, b""),
            (cli, srv, sport, 80, cs + 1 + q, ss + 1 + len(resp), 0x11, b""),
            (srv, cli, 80, sport, ss + 1 + len(resp), cs + 2 + q, 0x11, b""),
            (cli, srv, sport, 80, cs + 2 + q, ss + 2 + len(resp), 0x10, b""),
        ]:
            t += 0.001
            frames.append((t, _pkt(*s)))
    with open(out_pcap, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts, fr in frames:
            f.write(struct.pack("<IIII", int(ts), int((ts % 1) * 1e6), len(fr), len(fr)) + fr)
    with open(out_index, "w", encoding="utf-8") as f:
        json.dump(index, f, ensure_ascii=False, indent=1)
    print(f"cases={len(cases)} frames={len(frames)}")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
