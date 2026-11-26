# anti-artex

자율 AI 침투 도구 ARTEX와 그 포크·재배포판에 대한 탐지 자료를 모은다.

여러 보고서와 저장소에 흩어진 ARTEX IOC와 탐지 룰의 유효성, 정확성, 실효성을 직접 확인하고 실측해서, 국내 운영자가 ARTEX에 대응할 때 믿고 참고할 수 있는 자료를 한곳에 쌓아 가는 것을 지향한다.

> 상태: 작업 중. 룰과 문서는 실측이 늘 때마다 갱신한다.

## 다루는 것

- **IOC 정리**: 공개 보고의 IOC를 원문과 대조하고, 지표마다 현재 상태와 권고 조치(차단·사냥·기록용·차단 금지)를 붙인다. → [`iocs/`](iocs/)
- **탐지 룰**: 타 저장소, 상용 플랫폼 등을 통해 공개된 ARTEX 탐지 룰은 격리 실험실의 실측 트래픽과 정상 트래픽에 돌려 탐지 여부와 오탐을 확인하고, 이들이 다루지 않는 지문만 Snort 3·Suricata 룰로 새로 만든다. 새 룰도 같은 시험을 거친다.
- **인프라·포크 추적**: 공개 정보와 제3자 색인만으로 ARTEX 인프라, LLM 중개 서비스, 포크·Docker 이미지 변화를 살핀다.

## 실험실

ARTEX를 원본 소스에서 빌드해 인터넷과 분리된 실험실에서 돌린다. 표적은 격리망 안의 연습용 취약 앱(OWASP Juice Shop)이다.

**실제 모델 대신 가짜 모델로 구동한다.** ARTEX는 모델 주소를 설정으로 받는다. 이 주소를 실험실 안의 OpenAI 호환 서버로 돌리고, 그 서버가 ARTEX의 각 역할(목표 분해·계획자·워커)에 정해 둔 도구 호출을 돌려준다.

- ARTEX 엔진(의도 생성, 워커 병렬 실행, 재시도, 작업 종료)과 도구(WebFetch, 스킬 스크립트, 워커 셸)는 실제로 동작한다. 표적에 가는 요청은 ARTEX가 만든 진짜 트래픽이다.
- 무엇을 언제 할지는 대본이 정해, 같은 트래픽을 몇 번이든 재현할 수 있다. 모델 거절, 비용, 외부 전송이 없다.
- 모델의 응답 지연은 분포로 바꿔 넣어(0초~25초) 지연에 따라 달라지는 것과 달라지지 않는 것을 나눈다.
- 비교를 위해 정상 트래픽(브라우저 사용자, 모니터링 curl, API 클라이언트 등)도 같은 실험실에서 캡처한다.

**뽑아내는 것**은 모델이 무엇을 시키든 ARTEX 코드가 만드는 부분이다.

<table>
<tr><th nowrap>항목</th><th>예&#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; </th></tr>
<tr><td nowrap>요청 모양</td><td>도구별 헤더 구성(WebFetch=Go 기본, 스킬 스크립트=Python urllib 기본). UA를 바꾼 포크도 클라이언트는 같다</td></tr>
<tr><td nowrap>편성 구조</td><td>동시 작업 줄기 수, 한 출발지에서 섞여 나오는 클라이언트 종류, 하위 작업의 중복 요청</td></tr>
<tr><td nowrap>시간 구조</td><td>요청 몰아치기 안의 간격과 몰아치기 모양, 모델 오류 재시도 간격</td></tr>
<tr><td nowrap>내장 행위</td><td>지시문·코드가 강제하는 행위와 그렇지 않은 행위(소스 분석과 함께 본다)</td></tr>
</table>

**한계**: 모델이 실제로 어떤 공격 전술을 고르는지는 이 방식으로 재현하지 않는다. 결과는 "ARTEX 도구 경로가 만드는 트래픽과 그에 대한 룰의 반응"까지만 말한다. 전술은 ARTEX 지시문 분석과 공개 침입 보고로 보완한다.

## 하지 않는 것

- 노출된 ARTEX 콘솔이나 IOC 호스트에 직접 접속
- 운영자 신원 추적, 역공격, 키·계정 무력화
- 유출물·악성 이미지 내려받기

## 구성

<table>
<tr><th nowrap>경로</th><th>내용&#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; </th></tr>
<tr><td nowrap><code>rules/snort3</code>, <code>rules/suricata</code></td><td>탐지 룰</td></tr>
<tr><td nowrap><code>rules/logs/</code></td><td>웹 접근 로그 사냥 룰(Sigma, KQL)</td></tr>
<tr><td nowrap><code>rules/draft/</code></td><td>실측으로 시험 중인 룰 초안</td></tr>
<tr><td nowrap><a href="iocs/"><code>iocs/</code></a></td><td>정제한 IOC(지금 상태와 권고 조치 포함)</td></tr>
<tr><td nowrap><code>tests/</code></td><td>회귀 시험 <code>run.sh</code>, 캡처 비교 <code>replay_compare.sh</code>, 분석 <code>rhythm.py</code>·<code>streams.py</code>·<code>score_sources.py</code>, 합성 케이스 <code>shape_fixtures.py</code></td></tr>
<tr><td nowrap><code>docs/fingerprints.md</code></td><td>트래픽 지문과 근거</td></tr>
<tr><td nowrap><code>docs/lab-mock-*.md</code></td><td>실험실 실측 기록</td></tr>
<tr><td nowrap><code>docs/forks-2026-11-21.json</code></td><td>포크 비교</td></tr>
</table>

## 룰 (v0.5.0)

> **최근 업데이트(2026-11-23, v0.5.0)**: 헤더 순서가 남지 않는 웹 접근 로그에서 쓰는 사냥 룰(Sigma·KQL)을 더했다. IDS 룰(Snort 3·Suricata) 동작은 v0.4.1과 같다. 지난 변경은 [CHANGELOG](CHANGELOG.md).

<table>
<tr><th nowrap>파일</th><th nowrap>엔진</th><th>최근 업데이트&#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; </th></tr>
<tr><td nowrap><a href="rules/suricata/anti-artex.rules">rules/suricata/anti-artex.rules</a></td><td nowrap>Suricata 7</td><td>2026-11-23, <a href="https://github.com/jsik22/anti-artex/releases/tag/v0.5.0">v0.5.0</a></td></tr>
<tr><td nowrap><a href="rules/snort3/anti-artex.rules">rules/snort3/anti-artex.rules</a></td><td nowrap>Snort 3</td><td>2026-11-23, <a href="https://github.com/jsik22/anti-artex/releases/tag/v0.5.0">v0.5.0</a></td></tr>
<tr><td nowrap><a href="rules/logs/">rules/logs/</a></td><td nowrap>Sigma·KQL</td><td>2026-11-23, <a href="https://github.com/jsik22/anti-artex/releases/tag/v0.5.0">v0.5.0</a></td></tr>
</table>

룰 파일은 버전마다 [릴리스](https://github.com/jsik22/anti-artex/releases)에도 올린다(파일 이름에 버전을 붙임).

<table>
<tr><th nowrap>sid</th><th>찾는 것&#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; </th><th>근거</th></tr>
<tr><td nowrap>9278301</td><td>UA <code>artex-enrich/</code></td><td><code>enrich/enrich.go</code></td></tr>
<tr><td nowrap>9278302</td><td>UA <code>norma/</code></td><td>Norma SDK <code>tool/webfetch.go</code></td></tr>
<tr><td nowrap>9278303</td><td>UA <code>Mozilla/5.0 (spa-api-recon</code></td><td><code>skills/api-recon/scripts/*.py</code></td></tr>
<tr><td nowrap>9278304</td><td>POLICY: UA <code>artex-selfupdate</code></td><td><code>selfupdate/*.go</code></td></tr>
<tr><td nowrap>9278305</td><td>백도어 콘솔 로그인 명령(<code>captcha</code> 값이 <code>!</code>로 시작)</td><td>제3자 포렌식(tomicdd/artex 이미지)</td></tr>
<tr><td nowrap>9278306</td><td>포크 enrich UA(artifex·antifox·wsartex·prtseek)</td><td>포크 비교</td></tr>
<tr><td nowrap>9278307</td><td>포크 도구 UA의 ARTEX 토큰(<code>(ARTEX)</code>, <code>ARTEX-…/</code>)</td><td>포크 비교</td></tr>
<tr><td nowrap>9278308</td><td>POLICY: 포크 자가 업데이트 UA</td><td>포크 비교</td></tr>
<tr><td nowrap>9278309~11</td><td>포크 정찰 UA(YCode-recon, prtseek, Artifex-ct-subs)</td><td>포크 비교</td></tr>
<tr><td nowrap>9278390</td><td>HUNT: 같은 출발지의 로그인 POST 30초 안 7건 이상</td><td>실험실 실측</td></tr>
<tr><td nowrap>9278394</td><td>HUNT: 브라우저 UA + Go 기본 헤더 모양(UA만 바꾼 포크)</td><td>실험실 실측·포크 비교</td></tr>
<tr><td nowrap>9278395</td><td>HUNT: 브라우저 UA + Python urllib 헤더 모양(UA만 바꾼 포크)</td><td>실험실 실측·포크 비교</td></tr>
<tr><td nowrap>9278396</td><td>HUNT: 브라우저 UA + Go 헤더 모양 + <code>Connection: close</code></td><td>최신 변형 실측</td></tr>
<tr><td nowrap>9278397</td><td>HUNT: 원 서버에 <code>Proxy-Connection</code> 헤더 도착</td><td>최신 변형 실측</td></tr>
</table>

### 룰별 설명

- **ARTEX 도구 UA(9278301~03)**: ARTEX가 직접 보내는 요청의 고정 UA다. 9278302(WebFetch `norma/`)는 비교한 포크가 모두 그대로 쓴 가장 질긴 지문이고, 9278303은 api-recon 스킬 스크립트다. 9278301(`artex-enrich/`)은 v0.3.15에 이 UA를 내는 코드가 있지만 호출하는 곳이 없어 이 버전에서는 울리지 않을 가능성이 크다.
- **POLICY(9278304·08)**: 내부망 ARTEX 콘솔의 자가 업데이트 흔적이다. 승인되지 않은 ARTEX가 내부에 있는지 본다.
- **백도어 이미지(9278305)**: 백도어가 든 Docker 이미지로 띄운 콘솔에 들어오는 로그인 명령이다. 내부 ARTEX 콘솔이 남에게 장악당하는 시도를 본다.
- **포크 UA(9278306~11)**: 포크가 자기 이름으로 바꾼 UA다(포크 34개 비교).
- **로그인 연속(9278390, HUNT)**: 워커가 curl로 보내는 로그인 변형 반복이다. ARTEX 전용이 아닌 자동화 공격 일반 신호라 단독으로 ARTEX라고 판단하지 않는다.
- **브라우저 위장(9278394·95·96, HUNT)**: UA만 브라우저로 바꾼 변형을 잡는다. UA는 바꿔도 요청을 보내는 Go·Python 클라이언트의 헤더 모양은 그대로다. 원 개발자 계열 v0.3.30은 도구 UA를 브라우저 UA 20개 중 하나로 무작위로 바꾸는데, 실측에서 ARTEX 도구 요청을 모두 잡았다. 9278396은 v0.7.0 WebFetch와 기록 프록시가 다시 쓴 요청의 모양이다. 브라우저 UA를 흉내 내는 다른 수집기(httpx·katana 등)도 걸린다.
- **기록 프록시 누출(9278397, HUNT)**: ARTEX의 기록 프록시(traffic_capture)를 켜면 셸 도구 요청에 프록시용 `Proxy-Connection` 헤더가 남아 표적까지 간다. UA와 무관하다. 오래된 프록시가 같은 헤더를 흘리는 경우가 있어 사냥용이다.

sid는 지역 룰 범위로 임의로 붙인 값이니 환경에 맞게 바꾼다. HUNT 룰은 사냥용이다.

### 만든 과정

1. **소스 분석(v0.1.0)**: ARTEX v0.3.15와 Norma SDK 소스를 텍스트로 읽어 고정 UA와 요청 경로를 뽑았다.
2. **포크 비교(v0.2.0)**: 공개 포크 34개를 원본과 비교해 UA를 바꾼 포크를 찾았다.
3. **실험실 실측(v0.3.0)**: 가짜 모델로 ARTEX를 돌려 실제 트래픽을 캡처하고, 공개 룰 묶음과 이 저장소 룰을 함께 돌렸다. 공개 룰이 놓친 워커 curl 공격과 UA를 바꾼 포크를 겨냥해 룰을 더했다. 실패한 후보(404 급증, 브라우저 헤더 유무)는 `rules/draft/`와 실측 기록에 남겼다.
4. **최신 변형 실측(v0.4.0)**: 현장에서 쓰이는 최신 변형 두 계열(영문 재배포판 v0.7.0, 원 개발자 계열 v0.3.30)을 빌드해 같은 방식으로 쟀다([실측 기록](docs/lab-mock-2026-11-22.md)). 소음 조절, 기록 프록시, 이미지에 든 스캐너·헤드리스 브라우저 트래픽도 캡처했다.
5. **대량 실행(v0.5.0)**: 대본을 무작위로 조합해 ARTEX를 112회 돌리고, 정상 트래픽 출발지 103개와 함께 행동 신호를 평가했다([실측 기록](docs/lab-mock-2026-11-23.md)). 결과로 로그 사냥 룰을 더했다.
6. **회귀 시험**: 버전마다 합성 pcap 시험을 통과해야 올린다.

### 알려진 한계

- 모델이 ARTEX 도구 대신 curl·Python만 쓰면 ARTEX 고유 신호가 사라진다. 그때는 일반 웹 공격 탐지(페이로드 룰, WAF)의 영역이다.
- 헤더 모양 룰은 암호화된 HTTPS에서는 보이지 않는다. TLS를 푸는 지점(WAF, 리버스 프록시, 복호 센서)에 둔다.
- UA 룰은 UA를 바꾸면 놓친다. 원 개발자 계열 v0.3.30은 기본값으로 무작위 브라우저 UA를 쓴다(실측).

### 회귀 시험

```
bash tests/run.sh RESULTS.md
```

- [`tests/fixtures.py`](tests/fixtures.py)가 합성 pcap을 만든다(문서용 주소, 네트워크 전송 없음). 소스·포크에서 옮긴 요청 모양, 실측 헤더 모양, 다른 출발지의 로그인 연속, 정상 대조 케이스가 들어 있다.
- Suricata(`jasonish/suricata:7.0`)와 Snort 3(`ciscotalos/snort3`) 컨테이너를 `--network none`으로 돌려 문법 검사와 pcap 실행을 하고, [`tests/score.py`](tests/score.py)가 채점한다.
- 통과 기준: 공격형 케이스를 모두 잡고(알려진 공백 제외) 정상 케이스 오탐 0. Suricata는 단일 스레드로 돌린다(여러 스레드로 pcap을 재생하면 연속 횟수 룰의 결과가 흔들린다).
- 최근 결과: [`RESULTS.md`](RESULTS.md). v0.5.0은 두 엔진 모두 공격형 31/31, 정상 26/26(오탐 0).

### 공개 묶음과 비교

2026-11-22 실험실 캡처에서 ARTEX 전용 룰의 경보 수를 셌다. ARTEX는 버전마다 같은 대본으로 2회씩(요청 56건) 돌렸고, 오탐은 ARTEX 없이 만든 정상 트래픽 2개(요청 160건)에서 셌다. MMD는 MalwareMustDie MMD-072-2026, Theori는 Theori aipt-detections다.

<table>
<tr><th nowrap>묶음</th><th nowrap>ARTEX v0.7.0&#12288; &#12288; &#12288; &#12288; </th><th nowrap>ARTEX v0.3.30&#12288; &#12288; &#12288; </th><th nowrap>오탐&#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; </th></tr>
<tr><td nowrap>anti-artex(Snort 3·Suricata)</td><td nowrap>24</td><td nowrap>24</td><td nowrap>0</td></tr>
<tr><td nowrap>Theori(Suricata)</td><td nowrap>24</td><td nowrap>0</td><td nowrap>0</td></tr>
<tr><td nowrap>MMD(Snort 3·Suricata)</td><td nowrap>6</td><td nowrap>0</td><td nowrap>0</td></tr>
</table>

- v0.7.0은 ARTEX 도구 UA(`norma/0.4`, `spa-api-recon`)를 그대로 써서 UA 룰에 걸린다. v0.3.30은 도구 UA를 무작위 브라우저 UA로 바꿔 UA 룰이 걸리지 않고, anti-artex의 헤더 모양 룰(9278394·95)만 잡았다.
- v0.7.0에서 기록 프록시를 켜면 anti-artex의 `Proxy-Connection` 룰(9278397)이 32건을 더 잡았다.
- curl·Python 같은 도구 UA나 요청 빈도를 보는 범용 룰(MMD 일반 도구 경고, anti-artex 로그인 연속)은 정상 운영 트래픽에서도 울릴 수 있어 표에서 뺐다.
- 원본의 마지막 공개 버전 v0.3.15는 v0.7.0과 같은 모양이었다([1회차 실측 기록](docs/lab-mock-2026-11-21.md)).
- MMD 4260110은 Suricata 7.0.17에서 로드되지 않는다(`http.host`와 `nocase` 조합).
- anti-artex 룰 중 9278301~04·07은 두 묶음에도 있다. 함께 쓰면 된다: [MalwareMustDie MMD-072-2026](https://blog.malwaremustdie.org/2026/11/mmd-072-2026-artex-detection-signature.html), [Theori aipt-detections](https://github.com/theori-io/aipt-detections).

## 로그 사냥 룰

헤더 순서가 남지 않는 웹 접근 로그(프록시, WAF, 웹 서버)에서 쓰는 룰이다. Sigma 상관 룰은 [`rules/logs/artex-hunt-webaccess.yml`](rules/logs/artex-hunt-webaccess.yml), KQL은 [`rules/logs/artex-hunt.kql`](rules/logs/artex-hunt.kql)에 있다.

<table>
<tr><th nowrap>룰</th><th>찾는 것&#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; </th></tr>
<tr><td nowrap>UA 다양성</td><td>한 출발지가 60초 안에 서로 다른 브라우저 UA를 4개 이상 쓴다. 요청마다 UA를 무작위로 바꾸는 계열</td></tr>
<tr><td nowrap>로그인 연속</td><td>한 출발지가 30초 안에 로그인 경로로 POST를 7건 이상 보낸다(IDS 9278390과 같은 기준, KQL)</td></tr>
<tr><td nowrap>도구 UA</td><td>ARTEX 도구·포크 UA(IDS 9278301~11과 같은 내용)</td></tr>
</table>

- 실험실 대량 실행(ARTEX 112회, 정상 출발지 103개)에서 UA 다양성은 v0.3.30 48회 중 29회를 잡았고 정상 출발지에서는 0이었다. 정상 표본의 NAT 출발지는 사람 2명까지라, 사람이 많은 사무실 NAT와 사내 프록시 출구는 제외 목록에 넣는다.
- 검증: Sigma는 sigma-cli 검사와 Splunk 변환, KQL은 Kusto 언어 분석기로 구문·의미 오류 0건을 확인했다. 실제 SIEM에서는 돌리지 않았다.

