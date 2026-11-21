# 회귀 시험 결과

- 실행: 2026-11-21T17:12Z
- 엔진: Suricata version 7.0.17, Snort++ 3.10.0.0

**suricata**: 공격형 26/26 탐지(알려진 공백 0) · 정상 23/23 조용(오탐 0)

| 케이스 | 묶음 | 기대 | 결과 | 설명 |
|---|---|---|---|---|
| E-enrich | source-shape | True | 탐지 9278301 | enrich/enrich.go:233 자산 보강 단발 GET, UA artex-enrich/1.0, Connection: close |
| N-webfetch | source-shape | True | 탐지 9278302 | Norma tool/webfetch.go WebFetch UA norma/0.4 |
| A-spider | source-shape | True | 탐지 9278303 | skills/api-recon/scripts/spider_mpa.py UA |
| A-static | source-shape | True | 탐지 9278303 | skills/api-recon/scripts/harvest_static.py UA |
| U-selfupdate | source-shape | True | 탐지 9278304 | selfupdate/github.go 자가 업데이트(운영자 쪽 egress, 정책 룰) |
| B-backdoor-login | report-shape | True | 탐지 9278305 | 백도어 이미지 tomicdd/artex 로그인 captcha '!' 접두 명령(제3자 포렌식 보고 모양) |
| B-backdoor-login-sp | report-shape | True | 탐지 9278305 | 같은 모양, JSON 공백 변형 |
| X-browser | benign | False | - | 일반 브라우저 GET |
| X-curl | benign | False | - | curl GET |
| X-normalizer | benign | False | - | norma로 시작하지만 다른 UA(normalizer/2.0) |
| X-norma-mid | benign | False | - | UA 가운데에 norma/ 문자열 |
| X-artex-in-query | benign | False | - | UA는 브라우저, 쿼리에 artex-enrich/ 문자열 |
| X-spa-word | benign | False | - | 괄호 없는 spa-api-recon 언급 UA |
| X-login-captcha | benign | False | - | 정상 로그인 captcha 값 |
| X-login-nocaptcha | benign | False | - | captcha 없는 로그인 |
| X-other-login-bang | benign | False | - | 다른 경로의 captcha '!' 값 |
| X-github-ui | benign | False | - | GitHub API 일반 UA |
| F-artifex-enrich | fork-shape | True | 탐지 9278306 | 포크 16 enrich UA |
| F-antifox-enrich | fork-shape | True | 탐지 9278306 | AntiFox 포크 enrich UA |
| F-wsartex-enrich | fork-shape | True | 탐지 9278306 | 포크 20 enrich UA |
| F-prtseek-enrich | fork-shape | True | 탐지 9278306 | prtseek enrich UA |
| F-artex-http-shell | fork-shape | True | 탐지 9278307 | 포크 05·focus-agent http_shell UA |
| F-artex-nuclei-fp | fork-shape | True | 탐지 9278307 | 포크 19 Nuclei 지문 UA |
| F-artex-subfinder | fork-shape | True | 탐지 9278307 | 포크 19 Subfinder MCP UA |
| F-ycode-recon | fork-shape | True | 탐지 9278309 | ycode-auto-pentest recon UA |
| F-prtseek-obs | fork-shape | True | 탐지 9278310 | prtseek HTTP 관찰 UA |
| F-artifex-ct | fork-shape | True | 탐지 9278311 | ARTIFEX 인증서 하위 도메인 UA |
| F-scopeweaver-upd | fork-shape | True | 탐지 9278308 | ScopeWeaver 포크 자가 업데이트(POLICY) |
| F-pojun-upd | fork-shape | True | 탐지 9278308 | 포크 30 자가 업데이트(POLICY) |
| F-artex-update-check | fork-shape | True | 탐지 9278308 | 포크 01 업데이트 확인(POLICY) |
| X-enrich-generic | benign | False | - | 다른 제품의 -enrich UA |
| X-artexpo | benign | False | - | ARTEX 비슷한 단어가 든 UA |
| X-prtseek-word | benign | False | - | prtseek 블로그 방문 브라우저(쿼리) |
| S-go-chrome | fork-ua | True | 탐지 9278394 | WebFetch 모양 + Chrome UA(브라우저 UA 무작위 포크 흉내) |
| S-go-firefox | fork-ua | True | 탐지 9278394 | WebFetch 모양 + Firefox UA(Norma 검색 백엔드 UA) |
| S-urllib-chrome | fork-ua | True | 탐지 9278395 | api-recon 스크립트 모양 + Chrome UA |
| S-go-norma | orig | None | 탐지 9278302 | WebFetch 원래 모양(norma/0.4) |
| S-urllib-spa | orig | None | 탐지 9278303 | api-recon 원래 모양 |
| B-chrome-nav | benign | False | - | Chrome 페이지 이동(실측) |
| B-chrome-xhr | benign | False | - | Chrome XHR(실측) |
| B-go-default | benign | False | - | Go 프로그램 기본 UA(정직한 Go 도구) |
| B-urllib-default | benign | False | - | Python urllib 기본 UA(실측) |
| B-curl | benign | False | - | curl 기본(실측) |
| B-wget | benign | False | - | wget 기본(실측) |
| B-go-with-accept | benign | False | - | Go 클라이언트가 Accept까지 넣은 브라우저 흉내(모양 다름) |
| L-burst-1 | behavior | None | - | 로그인 POST 연속 1번째(실측 모양: 워커 curl) |
| L-burst-2 | behavior | None | - | 로그인 POST 연속 2번째(실측 모양: 워커 curl) |
| L-burst-3 | behavior | None | - | 로그인 POST 연속 3번째(실측 모양: 워커 curl) |
| L-burst-4 | behavior | None | - | 로그인 POST 연속 4번째(실측 모양: 워커 curl) |
| L-burst-5 | behavior | None | - | 로그인 POST 연속 5번째(실측 모양: 워커 curl) |
| L-burst-6 | behavior | None | - | 로그인 POST 연속 6번째(실측 모양: 워커 curl) |
| L-burst-7 | behavior | True | 탐지 9278390 | 로그인 POST 연속 7번째(실측 모양: 워커 curl) |
| L-burst-8 | behavior | True | 탐지 9278390 | 로그인 POST 연속 8번째(실측 모양: 워커 curl) |
| L-burst-9 | behavior | True | 탐지 9278390 | 로그인 POST 연속 9번째(실측 모양: 워커 curl) |
| L-human-1 | benign | False | - | 사람 로그인 1번째(틀리고 다시) |
| L-human-2 | benign | False | - | 사람 로그인 2번째(틀리고 다시) |
| L-human-3 | benign | False | - | 사람 로그인 3번째(틀리고 다시) |

**snort**: 공격형 26/26 탐지(알려진 공백 0) · 정상 23/23 조용(오탐 0)

| 케이스 | 묶음 | 기대 | 결과 | 설명 |
|---|---|---|---|---|
| E-enrich | source-shape | True | 탐지 9278301 | enrich/enrich.go:233 자산 보강 단발 GET, UA artex-enrich/1.0, Connection: close |
| N-webfetch | source-shape | True | 탐지 9278302 | Norma tool/webfetch.go WebFetch UA norma/0.4 |
| A-spider | source-shape | True | 탐지 9278303 | skills/api-recon/scripts/spider_mpa.py UA |
| A-static | source-shape | True | 탐지 9278303 | skills/api-recon/scripts/harvest_static.py UA |
| U-selfupdate | source-shape | True | 탐지 9278304 | selfupdate/github.go 자가 업데이트(운영자 쪽 egress, 정책 룰) |
| B-backdoor-login | report-shape | True | 탐지 9278305 | 백도어 이미지 tomicdd/artex 로그인 captcha '!' 접두 명령(제3자 포렌식 보고 모양) |
| B-backdoor-login-sp | report-shape | True | 탐지 9278305 | 같은 모양, JSON 공백 변형 |
| X-browser | benign | False | - | 일반 브라우저 GET |
| X-curl | benign | False | - | curl GET |
| X-normalizer | benign | False | - | norma로 시작하지만 다른 UA(normalizer/2.0) |
| X-norma-mid | benign | False | - | UA 가운데에 norma/ 문자열 |
| X-artex-in-query | benign | False | - | UA는 브라우저, 쿼리에 artex-enrich/ 문자열 |
| X-spa-word | benign | False | - | 괄호 없는 spa-api-recon 언급 UA |
| X-login-captcha | benign | False | - | 정상 로그인 captcha 값 |
| X-login-nocaptcha | benign | False | - | captcha 없는 로그인 |
| X-other-login-bang | benign | False | - | 다른 경로의 captcha '!' 값 |
| X-github-ui | benign | False | - | GitHub API 일반 UA |
| F-artifex-enrich | fork-shape | True | 탐지 9278306 | 포크 16 enrich UA |
| F-antifox-enrich | fork-shape | True | 탐지 9278306 | AntiFox 포크 enrich UA |
| F-wsartex-enrich | fork-shape | True | 탐지 9278306 | 포크 20 enrich UA |
| F-prtseek-enrich | fork-shape | True | 탐지 9278306 | prtseek enrich UA |
| F-artex-http-shell | fork-shape | True | 탐지 9278307 | 포크 05·focus-agent http_shell UA |
| F-artex-nuclei-fp | fork-shape | True | 탐지 9278307 | 포크 19 Nuclei 지문 UA |
| F-artex-subfinder | fork-shape | True | 탐지 9278307 | 포크 19 Subfinder MCP UA |
| F-ycode-recon | fork-shape | True | 탐지 9278309 | ycode-auto-pentest recon UA |
| F-prtseek-obs | fork-shape | True | 탐지 9278310 | prtseek HTTP 관찰 UA |
| F-artifex-ct | fork-shape | True | 탐지 9278311 | ARTIFEX 인증서 하위 도메인 UA |
| F-scopeweaver-upd | fork-shape | True | 탐지 9278308 | ScopeWeaver 포크 자가 업데이트(POLICY) |
| F-pojun-upd | fork-shape | True | 탐지 9278308 | 포크 30 자가 업데이트(POLICY) |
| F-artex-update-check | fork-shape | True | 탐지 9278308 | 포크 01 업데이트 확인(POLICY) |
| X-enrich-generic | benign | False | - | 다른 제품의 -enrich UA |
| X-artexpo | benign | False | - | ARTEX 비슷한 단어가 든 UA |
| X-prtseek-word | benign | False | - | prtseek 블로그 방문 브라우저(쿼리) |
| S-go-chrome | fork-ua | True | 탐지 9278394 | WebFetch 모양 + Chrome UA(브라우저 UA 무작위 포크 흉내) |
| S-go-firefox | fork-ua | True | 탐지 9278394 | WebFetch 모양 + Firefox UA(Norma 검색 백엔드 UA) |
| S-urllib-chrome | fork-ua | True | 탐지 9278395 | api-recon 스크립트 모양 + Chrome UA |
| S-go-norma | orig | None | 탐지 9278302 | WebFetch 원래 모양(norma/0.4) |
| S-urllib-spa | orig | None | 탐지 9278303 | api-recon 원래 모양 |
| B-chrome-nav | benign | False | - | Chrome 페이지 이동(실측) |
| B-chrome-xhr | benign | False | - | Chrome XHR(실측) |
| B-go-default | benign | False | - | Go 프로그램 기본 UA(정직한 Go 도구) |
| B-urllib-default | benign | False | - | Python urllib 기본 UA(실측) |
| B-curl | benign | False | - | curl 기본(실측) |
| B-wget | benign | False | - | wget 기본(실측) |
| B-go-with-accept | benign | False | - | Go 클라이언트가 Accept까지 넣은 브라우저 흉내(모양 다름) |
| L-burst-1 | behavior | None | - | 로그인 POST 연속 1번째(실측 모양: 워커 curl) |
| L-burst-2 | behavior | None | - | 로그인 POST 연속 2번째(실측 모양: 워커 curl) |
| L-burst-3 | behavior | None | - | 로그인 POST 연속 3번째(실측 모양: 워커 curl) |
| L-burst-4 | behavior | None | - | 로그인 POST 연속 4번째(실측 모양: 워커 curl) |
| L-burst-5 | behavior | None | - | 로그인 POST 연속 5번째(실측 모양: 워커 curl) |
| L-burst-6 | behavior | None | - | 로그인 POST 연속 6번째(실측 모양: 워커 curl) |
| L-burst-7 | behavior | True | 탐지 9278390 | 로그인 POST 연속 7번째(실측 모양: 워커 curl) |
| L-burst-8 | behavior | True | 탐지 9278390 | 로그인 POST 연속 8번째(실측 모양: 워커 curl) |
| L-burst-9 | behavior | True | 탐지 9278390 | 로그인 POST 연속 9번째(실측 모양: 워커 curl) |
| L-human-1 | benign | False | - | 사람 로그인 1번째(틀리고 다시) |
| L-human-2 | benign | False | - | 사람 로그인 2번째(틀리고 다시) |
| L-human-3 | benign | False | - | 사람 로그인 3번째(틀리고 다시) |

