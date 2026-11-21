# CHANGELOG

## v0.2.0 (2026-11-21)

- 포크 34개 비교 결과 반영: 포크 enrich UA 4종(9278306), 포크 도구 UA(ARTEX 토큰 9278307, YCode-recon 9278309, prtseek 9278310, Artifex-ct-subs 9278311), 포크 자가 업데이트 POLICY(9278308).
- `norma/0.4`는 모든 포크에서 그대로였다(9278302가 가장 질긴 지문).
- 시험: 포크 모양 13개, 정상 대조 3개 추가.

## v0.1.0 (2026-11-21)

- 첫 룰: UA 4종(artex-enrich, norma, spa-api-recon 2종을 한 룰로, artex-selfupdate 정책 룰), 백도어 이미지 로그인 명령(captcha '!' 접두).
- 근거: ARTEX v0.3.15 소스·Norma SDK 정적 분석(docs/fingerprints.md). 실측 전.
