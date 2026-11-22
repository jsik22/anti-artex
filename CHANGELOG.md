# CHANGELOG

## v0.4.1 (2026-11-22)

- Snort 3의 헤더 모양 룰 9278394·9278395를 Suricata와 같은 기준으로 맞춤(rev 2). 헤더 이름과 순서만 보고 값은 보지 않는다. 전에는 Snort 3만 `Accept-Encoding: gzip`(94), `Accept-Encoding: identity`·`Connection: close`(95) 값까지 요구해, 값이 다른 변형에서 두 엔진 결과가 갈릴 수 있었다.
- 시험: 값만 다른 모양 케이스 2개 추가.

## v0.4.0 (2026-11-22)

- 최신 변형 실측(영문 재배포판 v0.7.0, 원 개발자 계열 v0.3.30) 근거 룰 2개 추가. 근거와 시험은 docs/lab-mock-2026-11-22.md.
  - 9278396 HUNT: UA는 브라우저인데 헤더가 Go 기본 모양 + `Connection: close`. v0.7.0 WebFetch 모양, 기록 프록시가 다시 쓴 api-recon 요청. 9278394가 놓치던 경우.
  - 9278397 HUNT: 원 서버에 `Proxy-Connection` 헤더가 도착. ARTEX 기록 프록시(traffic_capture)를 거친 셸 도구 요청에 남는다. UA와 무관하다.
- 실측: UA를 무작위로 바꾸는 원 개발자 계열에서 헤더 모양 룰(9278394·95)이 ARTEX 도구 요청 24건을 모두 잡았다. 같은 캡처에서 공개 묶음은 Theori 0건, MMD 일반 curl 경고뿐이었다.
- 시험: 요청 모양 케이스 6개(탐지 3, 정상 3) 추가.

## v0.3.0 (2026-11-22)

- 실험실 실측(가짜 모델로 ARTEX 엔진 구동) 근거 룰 3개를 정식 룰로 올림. 근거와 시험은 docs/lab-mock-2026-11-21.md.
  - 9278390 HUNT: 로그인 경로 POST가 같은 출발지에서 30초 안에 7건 이상. 워커가 curl로 보내는 로그인 변형 반복을 잡는다. ARTEX 전용이 아닌 자동화 공격 일반 신호.
  - 9278394 HUNT: UA는 브라우저(`Mozilla/5.0`)인데 헤더가 Go 기본 모양(Host, User-Agent, Accept-Encoding)뿐. WebFetch·enrich의 UA만 바꾼 포크.
  - 9278395 HUNT: UA는 브라우저인데 헤더가 Python urllib 기본 모양. api-recon 스크립트의 UA만 바꾼 포크.
- 시험: 요청 모양 케이스 12개(실측 헤더 모양), 로그인 연속 케이스(다른 출발지 9건, 사람 모양 3건) 추가. 시험 도구가 케이스별 출발지를 받는다.
- 시험 환경: Suricata를 단일 스레드(`--runmode single`)로 돌리고 시험 pcap을 고정 seed로 만든다. 다중 스레드로 pcap을 재생하면 출발지 기준 `detection_filter`(9278390) 경보 수가 흐름 처리 순서에 따라 달라졌다(11-21 미해결 항목의 원인).
- 공개 묶음(MalwareMustDie·Theori)에 없는 유형이다. 헤더 모양 룰은 TLS를 푸는 지점(WAF·리버스 프록시·복호 센서)에서만 쓸 수 있다.

## v0.2.0 (2026-11-21)

- 포크 34개 비교 결과 반영: 포크 enrich UA 4종(9278306), 포크 도구 UA(ARTEX 토큰 9278307, YCode-recon 9278309, prtseek 9278310, Artifex-ct-subs 9278311), 포크 자가 업데이트 POLICY(9278308).
- `norma/0.4`는 모든 포크에서 그대로였다(9278302가 가장 질긴 지문).
- 시험: 포크 모양 13개, 정상 대조 3개 추가.

## v0.1.0 (2026-11-21)

- 첫 룰: UA 4종(artex-enrich, norma, spa-api-recon 2종을 한 룰로, artex-selfupdate 정책 룰), 백도어 이미지 로그인 명령(captcha '!' 접두).
- 근거: ARTEX v0.3.15 소스·Norma SDK 정적 분석(docs/fingerprints.md). 실측 전.
