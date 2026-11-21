# ARTEX 트래픽 지문 (1차, 2026-11-21)

근거: ARTEX v0.3.15 원본 백업(커밋 f3e3f54)과 한국어·영문 재배포판(06b36d7), 에이전트 SDK Autumn-27/Norma의 `tool/webfetch.go`·`tool/websearch.go`를 **텍스트로 읽은 결과**. 아직 실행 실측 전이다(관찰 = 소스에 그대로 있음, 추론 = 소스에서 끌어낸 동작).

## 표적 쪽에서 보이는 것 (네트워크 룰 대상)

<table>
<tr><th nowrap>지문</th><th>발생 위치와 소스 근거</th><th>공개 묶음(11-21 대조)&#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; </th></tr>
<tr><td nowrap>UA <code>artex-enrich/1.0</code></td><td>자산 보강 조회(단발 GET). <code>enrich/enrich.go:233</code>. v0.3.15에는 호출처가 없음(11-21 확인)</td><td>있음(MMD·Theori)</td></tr>
<tr><td nowrap>UA <code>norma/0.4</code></td><td>워커 WebFetch 도구, 30초 제한. Norma <code>tool/webfetch.go</code></td><td>있음(MMD·Theori)</td></tr>
<tr><td nowrap>UA spa-api-recon spider</td><td>api-recon 스킬의 MPA 크롤러. <code>spider_mpa.py:22</code></td><td>있음(Theori 10-09, MMD 11-16)</td></tr>
<tr><td nowrap>UA spa-api-recon</td><td>api-recon 스킬의 정적 자원 수집. <code>harvest_static.py:23</code></td><td>있음(Theori 10-09, MMD 11-16)</td></tr>
<tr><td nowrap>헤드리스 Chromium</td><td>api-recon 런타임 수집, playwright-cli 스킬. <code>runtime_harvest.js:100</code></td><td>없음(일반 헤드리스 탐지 영역)</td></tr>
<tr><td nowrap>외부 도구 UA</td><td>워커 셸이 부르는 도구(curl·Python 등)의 기본 UA. 프롬프트·모델에 따라 달라짐</td><td>일반 도구 룰 영역</td></tr>
</table>

- **추론**: UA 네 가지는 운영자가 바꿀 수 있지만, 기본 설정을 그대로 쓰는 사용자(이 프로젝트가 겨냥하는 층)는 바꾸지 않는다. 네 가지 모두 공개 묶음에 이미 있다.
- **정정(11-21)**: 처음에는 `spa-api-recon` 2종이 "기존 공개 묶음에 없음"이라고 적었다. 한국어 재배포판(artex-global)의 detections 하나만 대조한 잘못이다. Theori aipt-detections(Suricata 9500004·9500005, Sigma 10-09)와 MalwareMustDie MMD-072-2026(SID 4260126, v1.1.4)에 이미 있다.
- **추론**: `spa-api-recon` UA는 `Mozilla/5.0 (` 접두사로 브라우저인 척하지만 괄호 안이 고정 문자열이라 오탐이 거의 없을 것이다(실측 필요).

## 운영자 쪽에서 보이는 것 (호스트·외부 노출)

<table>
<tr><th nowrap>지문</th><th>근거&#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; </th></tr>
<tr><td nowrap>관리 콘솔 8787/tcp, 기본 docker-compose가 <b>모든 인터페이스에 공개</b>(<code>"8787:8787"</code>)</td><td><code>docker-compose.yml:32</code></td></tr>
<tr><td nowrap>기록형 MITM 프록시 8788/tcp(로컬 바인딩)</td><td><code>docker-compose.yml:33</code></td></tr>
<tr><td nowrap>자가 업데이트 UA <code>artex-selfupdate</code>(GitHub로 나가는 요청)</td><td><code>selfupdate/github.go</code>, <code>stage.go</code></td></tr>
<tr><td nowrap>WebSearch(ddgs) 백엔드가 Firefox 128 UA로 <code>html.duckduckgo.com</code> 조회</td><td>Norma <code>tool/websearch.go:224</code></td></tr>
<tr><td nowrap>교전 범위(RoE) 승인 장치를 일부러 제거했다는 주석</td><td><code>guard/guard.go:4</code></td></tr>
</table>

## 백도어 이미지(제3자 포렌식)

- Blackfish Security의 정적 분석(darkfibr/artex-forensics, 2026-11-14): Docker Hub `tomicdd/artex`(8,817회 이상 받음)에 로그인 API의 숨은 `captcha` 필드로 root 명령을 실행하는 백도어가 있었다고 함. 이미지는 내려감.
- 우리가 받은 원본 소스에는 `captcha` 처리가 없다(관찰, 그 주장과 맞음).
- **탐지 후보**: 내 망 안에서 누군가 ARTEX 콘솔을 돌리고 있다면, 그 콘솔로 들어오는 `POST /api/auth/login` 본문의 `captcha` 값이 `!`로 시작하는 요청 = 백도어 악용 시도. 인터넷 노출 콘솔을 찾아 접속하는 일은 하지 않는다.

## FBI FLASH-20261113-001에서 가져올 행동 지표

원문(IC3, TLP:CLEAR, 13쪽)에는 UA 문자열이 없다. UA 룰은 MMD·Theori 공개 묶음이 이미 다룬다. 원문에 있는 네트워크·행동 지표:

<table>
<tr><th nowrap>지표</th><th>원문 근거</th><th>룰 후보&#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; </th></tr>
<tr><td nowrap>피해 서버에서 <code>api.db-ip.com</code> 조회(위치 확인)</td><td>Initial Recon</td><td>DNS·TLS SNI HUNT</td></tr>
<tr><td nowrap>명령 출력을 <code>webhook.site</code>(엔드포인트 교체)로 전송</td><td>Collection</td><td>DNS·TLS SNI HUNT</td></tr>
<tr><td nowrap>LLM API 도메인 egress(anthropic·deepseek·bigmodel·x.ai)</td><td>Network Indicators</td><td>서버 대역 POLICY(단독 경보는 소음)</td></tr>
<tr><td nowrap>LLM 재판매 게이트웨이(CLIProxyAPI, New API)</td><td>Information Requested</td><td>미정</td></tr>
<tr><td nowrap>로그인·검색 엔드포인트에 대한 고빈도 순차 열거, 작은 변형을 반복하는 실패 요청</td><td>HTTP request patterns, Attack Characteristics</td><td>실측 뒤 리듬 룰</td></tr>
<tr><td nowrap>하위 에이전트가 같은 요청을 중복으로 보냄</td><td>Attack Characteristics</td><td>실측 뒤</td></tr>
<tr><td nowrap>웹 디렉터리 퍼징 500회 이상</td><td>Initial Recon</td><td>일반 스캐너 룰 영역</td></tr>
</table>

## 다음

1. 격리 실험실에서 실제 트래픽 캡처(별도 실험실 저장소) → 위 표의 실측 확인, 요청 리듬·재시도 지문 추가
2. `rules/`에 Snort 3·Suricata 룰 초안, `tests/`에 회귀 시험
3. 포크 중 UA를 바꾼 판본이 있는지 포크별 diff
