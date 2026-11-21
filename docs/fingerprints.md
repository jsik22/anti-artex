# ARTEX 트래픽 지문 (1차, 2026-11-21)

근거: ARTEX v0.3.15 원본 백업(원본 v0.3.15 백업, 커밋 f3e3f54)과 한국어·영문 재배포판(한국어·영문 재배포판, 06b36d7), 에이전트 SDK Autumn-27/Norma의 `tool/webfetch.go`·`tool/websearch.go`를 **텍스트로 읽은 결과**. 아직 실행 실측 전이다(관찰 = 소스에 그대로 있음, 추론 = 소스에서 끌어낸 동작).

## 표적 쪽에서 보이는 것 (네트워크 룰 대상)

| 지문 | 발생 위치 | 소스 근거 | 기존 공개 묶음(artex-global detections) |
|---|---|---|---|
| UA `artex-enrich/1.0` | 자산 보강 조회(제목만 읽는 단발 GET) | `enrich/enrich.go:233` | 있음 |
| UA `norma/0.4` | 워커의 WebFetch 도구, 30초 제한 | Norma `tool/webfetch.go` (요청·재시도 둘 다) | 있음 |
| UA `Mozilla/5.0 (spa-api-recon spider)` | api-recon 스킬의 MPA 크롤러 | `skills/api-recon/scripts/spider_mpa.py:22` | **없음** |
| UA `Mozilla/5.0 (spa-api-recon)` | api-recon 스킬의 정적 자원 수집 | `skills/api-recon/scripts/harvest_static.py:23` | **없음** |
| 헤드리스 Chromium(playwright) | api-recon 런타임 수집, playwright-cli 스킬 | `runtime_harvest.js:100` (`headless: 'new'`) | 없음(일반 헤드리스 탐지 영역) |
| 워커가 부르는 외부 도구(nmap·nuclei 등)의 기본 UA·패턴 | 워커 셸 | 프롬프트·스킬에 따라 달라짐 | 일반 스캐너 룰 영역 |

- **추론**: UA 네 가지는 운영자가 바꿀 수 있지만, 기본 설정을 그대로 쓰는 사용자(이 프로젝트가 겨냥하는 층)는 바꾸지 않는다. 두 개는 기존 공개 묶음에도 없다.
- **추론**: `spa-api-recon` UA는 `Mozilla/5.0 (` 접두사로 브라우저인 척하지만 괄호 안이 고정 문자열이라 오탐이 거의 없을 것이다(실측 필요).

## 운영자 쪽에서 보이는 것 (호스트·외부 노출)

| 지문 | 근거 |
|---|---|
| 관리 콘솔 8787/tcp, 기본 docker-compose가 **모든 인터페이스에 공개**(`"8787:8787"`) | `docker-compose.yml:32` |
| 기록형 MITM 프록시 8788/tcp(로컬 바인딩) | `docker-compose.yml:33` |
| 자가 업데이트 UA `artex-selfupdate`(GitHub로 나가는 요청) | `selfupdate/github.go`, `stage.go` |
| WebSearch(ddgs) 백엔드가 Firefox 128 UA로 `html.duckduckgo.com` 조회 | Norma `tool/websearch.go:224` |
| 교전 범위(RoE) 승인 장치를 일부러 제거했다는 주석 | `guard/guard.go:4` |

## 백도어 이미지(제3자 포렌식)

- Blackfish Security의 정적 분석(darkfibr/artex-forensics, 2026-11-14): Docker Hub `tomicdd/artex`(8,817회 이상 받음)에 로그인 API의 숨은 `captcha` 필드로 root 명령을 실행하는 백도어가 있었다고 함. 이미지는 내려감.
- 우리가 받은 원본 소스에는 `captcha` 처리가 없다(관찰, 그 주장과 맞음).
- **탐지 후보**: 내 망 안에서 누군가 ARTEX 콘솔을 돌리고 있다면, 그 콘솔로 들어오는 `POST /api/auth/login` 본문의 `captcha` 값이 `!`로 시작하는 요청 = 백도어 악용 시도. 인터넷 노출 콘솔을 찾아 접속하는 일은 하지 않는다.

## 다음

1. 격리 실험실에서 실제 트래픽 캡처(별도 실험실 저장소) → 위 표의 실측 확인, 요청 리듬·재시도 지문 추가
2. `rules/`에 Snort 3·Suricata 룰 초안, `tests/`에 회귀 시험
3. 포크 중 UA를 바꾼 판본이 있는지 포크별 diff
