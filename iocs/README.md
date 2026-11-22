# ARTEX IOC

공개 보고서에 나온 ARTEX 관련 IOC를 원문과 다시 대조하고, 지표마다 지금 상태와 권고 조치를 붙였다.

> TLP:CLEAR. 기준일 2026-11-22. IP는 재할당될 수 있으니 차단 전에 자기 환경의 로그·문맥과 함께 확인한다.

## 파일

[`artex-iocs.csv`](artex-iocs.csv): 지표 139개(IPv4 67, User-Agent 35, 도메인 17, 컨테이너 이미지 9, Azure 앱 ID 7, 파일 해시 3, TLS 인증서 지문 1).

<table>
<tr><th nowrap>열</th><th>뜻&#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; </th></tr>
<tr><td nowrap>indicator</td><td>지표 값</td></tr>
<tr><td nowrap>type</td><td><code>ipv4</code>, <code>domain</code>, <code>container-image</code>, <code>azure-app-id</code>, <code>sha256</code>, <code>tls-cert-sha256</code>, <code>user-agent</code></td></tr>
<tr><td nowrap>status_YYYY-MM-DD</td><td>기준일의 상태. IP는 제3자 색인(Shodan InternetDB)의 최근 관측 여부, 도메인은 공개 리졸버 해석 결과, UA는 빈칸</td></tr>
<tr><td nowrap>recommendation</td><td>권고 조치(아래 표)</td></tr>
<tr><td nowrap>sources</td><td>지표가 나온 보고서. "MalwareMustDie 목록 경유"는 원문에서 확인하지 못하고 MMD-072-2026 IOC 목록으로 확인한 것</td></tr>
<tr><td nowrap>note</td><td>정상 서비스 사유, 인증서 설명 등</td></tr>
</table>

<table>
<tr><th nowrap>권고 조치</th><th>뜻&#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; </th></tr>
<tr><td nowrap>차단 검토</td><td>지금도 해석되는 도메인. 차단을 검토한다</td></tr>
<tr><td nowrap>사냥(로그 대조)</td><td>최근 관측이 있는 지표, ARTEX·포크 고유 User-Agent. 과거 로그와 대조한다</td></tr>
<tr><td nowrap>기록용</td><td>최근 관측이 없거나 해석되지 않는 지표. 과거 로그 대조용으로만 쓴다</td></tr>
<tr><td nowrap>도메인만 차단</td><td>CDN 뒤에 있는 도메인. IP로 막으면 무관한 서비스까지 막힌다</td></tr>
<tr><td nowrap>차단 금지, 사냥 전용</td><td>정상 서비스(위치 조회, 웹훅, OAST). 막지 말고 서버에서 나가는 연결을 찾는 데 쓴다</td></tr>
<tr><td nowrap>단독 판단 금지</td><td>정상 도구·라이브러리·브라우저도 쓰는 User-Agent. 다른 지표와 함께 볼 때만 쓴다</td></tr>
<tr><td nowrap>차단 금지</td><td>CDN·클라우드로 재할당됐거나 다른 서비스와 겹치는 IP</td></tr>
<tr><td nowrap>오기 의심</td><td>원문 안에서 값이 서로 다르다. 다른 쪽 값을 쓴다</td></tr>
</table>

## 싣지 않은 것

- **지금 ARTEX 콘솔이 열려 있는 IP 8개**: 공개하면 다른 사람이 콘솔을 가로챌 수 있어 뺐다.
- **공개 보고서에 없는 지표**: 공개 도메인을 따라가 새로 찾은 IP 등. 도메인이 지금 가리키는 IP 값도 싣지 않는다.
- **ARTEX가 아닌 사례의 지표**: 같은 보고서 안의 다른 공격 사례(예: JPCERT/CC 경보의 ARTEX 외 사례), 위치 설명용 네트워크 대역, 보고서 사이트 자체의 도메인.

## 만든 방법

1. 보고서 원문을 받아 IOC를 다시 뽑는다. 차단 화면은 추출하지 않고, 조회한 쪽의 공인 IP가 결과에 섞이지 않게 걸러 낸다.
2. 공개 IOC 목록(MalwareMustDie MMD-072-2026)과 대조해 빠진 것, 옮겨 적다 틀린 것, 출처 표기를 확인한다.
3. 지표마다 지금 상태를 붙인다. IOC 호스트에 직접 접속하지 않고 제3자 색인과 공개 리졸버만 쓴다.
4. 권고 조치를 붙이고 위 원칙대로 공개분을 고른다.

## 문자열 지표

- **콘솔 제목**: ARTEX 웹 콘솔 기본 제목은 <code>ARTEX - 自主渗透测试控制台</code>이다(웹 앱 기본값). 번역·수정한 변형(영어·한국어·일본어 등)도 쓰인다(Hunt.io). 기본 포트는 8787/tcp.
- **TLS 인증서 지문**: CSV의 <code>tls-cert-sha256</code>은 발급자 <code>O=ARTEX</code> 인증서다. ARTEX 원본 소스에 없는 설정이라 운영자·포크 쪽 값이다. 모든 ARTEX 콘솔에 있지는 않다.
- **운영자 파일 표식**: 파일 공유에 <code>artex_probe_*.txt</code>를 쓰고 지우는 정찰 흔적(Hunt.io). 운영자가 만든 이름이라 다른 운영자에게는 없을 수 있다.
- **User-Agent**: 공개 보고서에 나온 값은 CSV의 <code>user-agent</code>에 있다. 운영자가 쉽게 바꾸는 값이라 없다고 안심하지 않는다. ARTEX 원본 코드의 UA와 요청 모양은 저장소의 [룰](../README.md#룰-v030)을 본다.

## 출처

<table>
<tr><th nowrap>보고</th><th>글&#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; &#12288; </th></tr>
<tr><td nowrap>Bitrise</td><td><a href="https://bitrise.io/security-advisory-november-2026">security advisory november 2026</a></td></tr>
<tr><td nowrap>BleepingComputer</td><td><a href="https://www.bleepingcomputer.com/news/security/hackers-use-antifox-ai-agents-in-aws-credential-theft-attacks/">hackers use antifox ai agents in aws credential theft attacks</a></td></tr>
<tr><td nowrap>BleepingComputer</td><td><a href="https://www.bleepingcomputer.com/news/security/workos-says-attacker-used-artex-ai-to-breach-internal-sales-app/">workos says attacker used artex ai to breach internal sales app</a></td></tr>
<tr><td nowrap>Check Point</td><td><a href="https://research.checkpoint.com/2026/hacking-on-autopilot-inside-artex-cybercrime-campaigns/">hacking on autopilot inside artex cybercrime campaigns</a></td></tr>
<tr><td nowrap>CrowdStrike</td><td><a href="https://www.crowdstrike.com/en-us/blog/unknown-threat-actor-uses-artex-to-target-south-korean-finance/">unknown threat actor uses artex to target south korean finance</a></td></tr>
<tr><td nowrap>CrowdStrike</td><td><a href="https://www.crowdstrike.com/en-us/blog/vapor-panda-uses-artex-to-scale-global-campaign/">vapor panda uses artex to scale global campaign</a></td></tr>
<tr><td nowrap>Datadog Security Labs</td><td><a href="https://securitylabs.datadoghq.com/articles/artex-agentic-attacks-aws-environments/">artex agentic attacks aws environments</a></td></tr>
<tr><td nowrap>ExtraHop</td><td><a href="https://www.extrahop.com/blog/artext-inside-an-agentic-attack-framework">artext inside an agentic attack framework</a></td></tr>
<tr><td nowrap>Eye Security</td><td><a href="https://labs.eye.security/how-we-defended-against-an-ai-driven-attack/">how we defended against an ai driven attack</a></td></tr>
<tr><td nowrap>GitGuardian</td><td><a href="https://blog.gitguardian.com/an-artex-build-ships-no-secret-scanner-in-our-lab-it-found-the-secrets-anyway/">an artex build ships no secret scanner in our lab it found the secrets</a></td></tr>
<tr><td nowrap>Hunt.io</td><td><a href="https://hunt.io/blog/artex-south-korea-bank-infrastructure">artex south korea bank infrastructure</a></td></tr>
<tr><td nowrap>Huntress</td><td><a href="https://www.huntress.com/blog/vendor-credential-enables-unauthorized-access">vendor credential enables unauthorized access</a></td></tr>
<tr><td nowrap>JPCERT/CC</td><td><a href="https://www.jpcert.or.jp/at/2026/at260030.html">at260030.html</a></td></tr>
<tr><td nowrap>Microsoft</td><td><a href="https://www.microsoft.com/en-us/security/blog/2026/10/21/storm-0940-uses-artex-agentic-ai-connectwise-supply-chain-compromise/">storm 0940 uses artex agentic ai connectwise supply chain compromise</a></td></tr>
<tr><td nowrap>Microsoft</td><td><a href="https://www.microsoft.com/en-us/security/blog/2026/11/06/artex-abuse-expands-as-cybercriminals-target-financial-sector/">artex abuse expands as cybercriminals target financial sector</a></td></tr>
<tr><td nowrap>The Hacker News</td><td><a href="https://thehackernews.com/2026/11/backdoored-docker-image-for-artex-ai.html">backdoored docker image for artex ai.html</a></td></tr>
<tr><td nowrap>Unit 42</td><td><a href="https://unit42.paloaltonetworks.com/artex-and-ai-powered-red-teaming-tools/">artex and ai powered red teaming tools</a></td></tr>
<tr><td nowrap>Wiz</td><td><a href="https://www.wiz.io/blog/artex-in-the-wild-storm-0940-expands-targeting-of-it-and-software-vendors">artex in the wild storm 0940 expands targeting of it and software vend</a></td></tr>
<tr><td nowrap>Xint(Theori)</td><td><a href="https://xint.io/resources/artex-case-study-and-defense-guide">artex case study and defense guide</a></td></tr>
<tr><td nowrap>Zscaler</td><td><a href="https://www.zscaler.com/blogs/security-research/inside-global-ai-assisted-hacking-campaign">inside global ai assisted hacking campaign</a></td></tr>
</table>
