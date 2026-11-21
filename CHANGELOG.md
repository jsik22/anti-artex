# CHANGELOG

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
