#!/usr/bin/env python3
"""요청 모양(헤더 구성) 지문 시험용 합성 pcap. tests/fixtures.py의 pcap 작성기를 그대로 쓴다.

헤더 순서와 값은 2026-11-21 실험실 실측 캡처(가짜 모델로 구동한 ARTEX, 정상 클라이언트)에서 옮겼다.
UA만 바꾼 포크는 실험실에서 만들 수 없어(UA가 코드에 고정), 실측 헤더 모양에 포크가 쓰는 브라우저 UA를 넣어 흉내 낸다.

사용: python3 -I tests/shape_fixtures.py OUT.pcap OUT-index.json
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fixtures  # noqa: E402

H = "app.example.test"
CHROME = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
FIREFOX = "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"


def raw(method, path, headers, body=""):
    r = f"{method} {path} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in headers)
    return (r + "\r\n" + body).encode()


def go_shape(ua, path="/"):          # Norma WebFetch(Go net/http 기본): Host, User-Agent, Accept-Encoding: gzip
    return raw("GET", path, [("Host", H), ("User-Agent", ua), ("Accept-Encoding", "gzip")])


def urllib_shape(ua, path="/"):      # api-recon 스크립트(Python urllib): Accept-Encoding: identity, Host, User-Agent, Connection: close
    return raw("GET", path, [("Accept-Encoding", "identity"), ("Host", H), ("User-Agent", ua), ("Connection", "close")])


CASES = [
    # 탐지해야 함: 브라우저라고 주장하는 UA + ARTEX 도구의 실측 헤더 모양(UA를 바꾼 포크 흉내)
    ("S-go-chrome", "fork-ua", True, "WebFetch 모양 + Chrome UA(브라우저 UA 무작위 포크 흉내)", go_shape(CHROME)),
    ("S-go-firefox", "fork-ua", True, "WebFetch 모양 + Firefox UA(Norma 검색 백엔드 UA)", go_shape(FIREFOX, "/search?q=x")),
    ("S-urllib-chrome", "fork-ua", True, "api-recon 스크립트 모양 + Chrome UA", urllib_shape(CHROME, "/static/js/main.js")),
    # v0.4.1: 헤더 값이 기본값과 달라도 이름·순서가 같으면 두 엔진 모두 잡아야 함(Snort 3도 이름 기준)
    ("S-go-chrome-deflate", "fork-ua", True, "WebFetch 모양, Accept-Encoding 값만 다름 + Chrome UA", raw("GET", "/", [("Host", H), ("User-Agent", CHROME), ("Accept-Encoding", "gzip, deflate")])),
    ("S-urllib-chrome-gzip", "fork-ua", True, "api-recon 모양, 헤더 값만 다름 + Chrome UA", raw("GET", "/", [("Accept-Encoding", "gzip"), ("Host", H), ("User-Agent", CHROME), ("Connection", "keep-alive")])),
    # v0.4.0(2026-11-22 실측): v0.7.0 WebFetch는 Connection: close를 더하고, 기록 프록시는 urllib 요청을 같은 모양으로 다시 쓴다
    ("S-goconn-chrome", "fork-ua", True, "v0.7.0 WebFetch 모양(Connection: close 추가) + Chrome UA", raw("GET", "/", [("Host", H), ("User-Agent", CHROME), ("Accept-Encoding", "gzip"), ("Connection", "close")])),
    ("S-proxied-urllib", "fork-ua", True, "기록 프록시를 거친 api-recon 요청(실측: 원 개발자 계열 v0.3.30) + 브라우저 UA", raw("GET", "/main.js", [("Host", H), ("User-Agent", FIREFOX), ("Accept-Encoding", "identity"), ("Connection", "close")])),
    ("S-proxy-conn-curl", "proxy-leak", True, "기록 프록시를 거친 워커 curl(실측): Proxy-Connection이 원 서버까지 남음", raw("GET", "/rest/user/whoami", [("Host", H), ("User-Agent", "curl/7.88.1"), ("Accept", "*/*"), ("Proxy-Connection", "Keep-Alive")])),
    # 참고: 원래 UA 그대로(기존 UA 룰이 잡는 영역)
    ("S-go-norma", "orig", None, "WebFetch 원래 모양(norma/0.4)", go_shape("norma/0.4")),
    ("S-urllib-spa", "orig", None, "api-recon 원래 모양", urllib_shape("Mozilla/5.0 (spa-api-recon)")),
    # 탐지하면 안 됨: 정상 클라이언트 실측 모양
    ("B-chrome-nav", "benign", False, "Chrome 페이지 이동(실측)", raw("GET", "/", [("Host", H), ("Connection", "keep-alive"), ("Upgrade-Insecure-Requests", "1"), ("User-Agent", CHROME),
        ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"), ("Accept-Encoding", "gzip, deflate")])),
    ("B-chrome-xhr", "benign", False, "Chrome XHR(실측)", raw("GET", "/api/Products/1", [("Host", H), ("Connection", "keep-alive"), ("User-Agent", CHROME), ("Accept", "application/json, text/plain, */*"),
        ("Referer", f"http://{H}/"), ("Accept-Encoding", "gzip, deflate")])),
    ("B-go-default", "benign", False, "Go 프로그램 기본 UA(정직한 Go 도구)", go_shape("Go-http-client/1.1")),
    ("B-urllib-default", "benign", False, "Python urllib 기본 UA(실측)", urllib_shape("Python-urllib/3.12")),
    ("B-curl", "benign", False, "curl 기본(실측)", raw("GET", "/", [("Host", H), ("User-Agent", "curl/7.88.1"), ("Accept", "*/*")])),
    ("B-wget", "benign", False, "wget 기본(실측)", raw("GET", "/", [("Host", H), ("User-Agent", "Wget/1.21.3"), ("Accept", "*/*"), ("Accept-Encoding", "identity"), ("Connection", "Keep-Alive")])),
    ("B-go-conn-default", "benign", False, "Go 기본 UA + Connection: close(정직한 Go 도구)", raw("GET", "/", [("Host", H), ("User-Agent", "Go-http-client/1.1"), ("Accept-Encoding", "gzip"), ("Connection", "close")])),
    ("B-python-requests", "benign", False, "python-requests 기본 모양", raw("GET", "/", [("Host", H), ("User-Agent", "python-requests/2.32.3"), ("Accept-Encoding", "gzip, deflate"), ("Accept", "*/*"), ("Connection", "keep-alive")])),
    ("B-chrome-close", "benign", False, "Chrome이 Connection: close로 보낸 이동(헤더 많음)", raw("GET", "/", [("Host", H), ("Connection", "close"), ("User-Agent", CHROME), ("Accept", "text/html"), ("Accept-Encoding", "gzip, deflate"), ("Accept-Language", "ko-KR,ko;q=0.9")])),
    ("B-go-with-accept", "benign", False, "Go 클라이언트가 Accept까지 넣은 브라우저 흉내(모양 다름)", raw("GET", "/", [("Host", H), ("User-Agent", CHROME), ("Accept", "text/html"), ("Accept-Encoding", "gzip")])),
]

if __name__ == "__main__":
    fixtures.CASES = CASES
    fixtures.main(sys.argv[1], sys.argv[2], extra=False)
