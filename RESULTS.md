# 회귀 시험 결과

- 실행: 2026-11-21T03:15Z
- 엔진: Suricata version 7.0.17, Snort++ 3.10.0.0

**suricata**: 공격형 7/7 탐지(알려진 공백 0) · 정상 10/10 조용(오탐 0)

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

**snort**: 공격형 7/7 탐지(알려진 공백 0) · 정상 10/10 조용(오탐 0)

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

