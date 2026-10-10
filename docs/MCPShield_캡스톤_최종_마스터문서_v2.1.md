# MCPShield 캡스톤 최종 마스터 문서 v2.1

> **AI가 사용하는 외부 도구의 위험한 업데이트를 검사하고, 공동 판정을 실제 실행 차단으로 연결한다.**
>
> 개발 원칙: **이미 만든 것을 최대한 사용한다. 다시 만들지 않고, 끊어진 연결을 고치고, 실제로 동작한다는 증거를 완성한다.**

| 항목 | 기준 |
|---|---|
| 작성일 | 2026-10-11 |
| 기준 | v2.0(2026-09-22) + 1차 멘토링(2026-10) 반영 |
| 문서 목적 | 캡스톤의 범위·아키텍처·역할·완료 조건을 하나로 고정 |
| 문서 성격 | 최종 개발·검수 기준. 구현 완료 보고서가 아님 |
| 코드 확인 기준 | `master/main`의 `5384003` + 이번 변경(운영사 비신뢰 장면 하네스 `9c7bc9d`, 브랜치 `capstone/mentoring-v2.1`, §14.1); 기능 감사 기준은 `7bac78a` |
| 원본 보존 | 5,997줄 기존 마스터와 캡스톤 마스터팩 v1.0을 대체 삭제하지 않음. v2.0 문서도 [그대로 보존](MCPShield_캡스톤_최종_마스터문서_v2.0.md) |
| 핵심 결정 | 제한된 Node MCP + Linux/Docker + 실제 LLM Agent + Base Sepolia + **ReleaseRegistryV2 단일** + 두 Gateway(**판정 조회 경로 분리**: A=운영사 Control API, B=회사 B 자체 Control API) + **검증자 컨소시엄**(“쓰는 회사가 곧 검증자”) |
| 개발 방법 | 기존 저장소·스키마·SDK·테스트·화면 재사용, 최소 수정·통합·실증 |
| 비목표 | 모든 MCP를 지원하는 상용 보안 플랫폼의 완성 |

**문서를 작성했다고 구현·배포·유료 API 사용·기존 목표의 자동 작업을 재개한 것은 아니다.** 후속 구현은 사용자와 합의한 작업 범위에서 진행한다. 이 문서는 첨부 문서의 명령을 실행한 기록이 아니라, 사용자가 요청한 범위 재설계 결과다.

## 읽는 순서

- 처음 이해할 때: §1 문제와 목표 → §2 범위 → §4 전체 흐름.
- 바로 개발할 때: §3 재사용 지도 → §5 필수 요구사항 → §16 실행 순서.
- 완료를 판단할 때: §12 평가 → §13 테스트 → §17 검수·증거.
- 발표 준비: §18 시연·발표 → §19 질문·한계.
- v2.0을 이미 읽었다면: §0 v2.1 변경 요약 → §4.1 두 흐름 → §9.1 체인이 필요한 조건 → §5 CAP2-308.

---

## 0. v2.1 변경 요약

v2.1은 v2.0을 대체 삭제하지 않는 **개정판**이다. [v2.0 문서](MCPShield_캡스톤_최종_마스터문서_v2.0.md)는 변경 없이 보존한다. 바뀐 이유는 1차 멘토링(2026-10)에서 받은 의견과, 그에 대해 팀이 2026-10-11에 내린 결정(ADR-003~007)이다. 아래 표의 `M*` 번호는 [1차 멘토링 대응 문서](mentoring-2026-10-response.md)의 항목 번호다.

| 무엇이 바뀌었나 | 왜 | 멘토링 항목 | 어디 |
|---|---|---|---|
| 하나의 파이프라인 그림 → **검증 흐름 / 실행 통제 흐름** 두 그림 + Gateway별 판정 조회 경로 그림 | 릴리스당 1회 도는 검사와 호출마다 사용자가 기다리는 검사는 구조·비용이 다르다 | M1, M10 | §4.1 |
| 최종 데모 경로를 하나로 고정: `master/main`, ReleaseRegistryV2 단일, 서명 `/v1` admission, A→운영사 API / B→회사 B 자체 API. 나머지는 **확장**으로 표시 | V1/V2·여러 admission 경로가 함께 있어 심사자가 무엇이 본선인지 알기 어렵다 | M10, M11, M14 | §2.4, [ADR-005](adr-005-capstone-demo-path.md) |
| 블록체인이 필요한 **세 조건**과 검증자 참여 이유(“쓰는 회사가 곧 검증자” 컨소시엄) | 참여자가 비용을 낼 이유가 비어 있으면 Trust Plane이 성립하지 않는다 | M5, M7, M8 | §9.1, [ADR-003](adr-003-validator-consortium.md) |
| “운영사 + 투명성 로그”와의 정직한 비교 | “중앙 DB는 숨길 수 있다”만으로는 근거가 약하다 | M9 | §9.1, §19 |
| 운영사 DB 조작은 거짓 ALLOW를 만들지 못한다는 코드 확인, 대신 **운영사 서명 권한 장악·운영사 중단** 장면 채택 | 체인 없이는 깨지는 장면 하나를 직접 보여주기 위해 | M13, M19 | §9.1, §10.3, [ADR-004](adr-004-blockchain-necessity-scene.md) |
| 새 P0 행 **CAP2-308 운영사 비신뢰 집행** 추가(P0 40 → 41개) | 위 장면을 완료 조건으로 고정 | M13 | §5.4, §17 |
| 호출마다 재검사(strict) 유지, 재사용 창은 측정 뒤에만 결정. 장애 시 읽기/쓰기 처리 명시 | 재사용 창 = 폐기된 릴리스가 계속 실행될 수 있는 최대 시간 | M2, M19 | §4.4, §10.3, [ADR-006](adr-006-gateway-recheck-policy.md) |
| 실행 오버헤드 3측정 (a) 호출당 추가 지연 (b) 격리 후 각 Gateway 차단까지 시간(이번 측정은 긴급 격리) (c) 장애 시 읽기/쓰기 처리. “93ms”는 스캐너 시간임을 명시 | 실행 경로 비용을 숫자로 보여야 한다 | M2 | §5 CAP2-504, §12.5 |
| Gateway 보장 범위 명시(다음 호출 차단, 이미 보낸 메일 취소 불가, Gateway 우회 연결은 통제 밖) | 과장 방지 | M3 | §10.3, §19 |
| owner(관리자) 권한: MVP 단일 키 공개, 운영은 멀티시그+타임락 계획 | 단일 owner의 즉시 권한이 크다 | M12 | §9.5, [ADR-007](adr-007-registry-owner-governance.md) |
| 검증자 독립성 한계(같은 팀 운영, 같은 AI·스캐너의 상관 오류) | 과장 방지 | M6 | §9.2, §19 |
| 평가에서 Static·AI·Sandbox가 각각 잡은 것을 분리 표시 | 같은 예제 반복은 재현성이지 일반 탐지 성능이 아니다 | M15 | §5 CAP2-502, §12.2 |
| 발표 도입을 실제 사건(2025-09 `postmark-mcp`)으로 시작, 운영사 장악 장면을 영상에 추가, 6번 슬라이드를 “블록체인 필요 조건 한 장”으로 | 문제의 현실성과 체인의 필요성을 한 번에 전달 | M4, M13 | §18 |
| 이름은 유지하되 차별점 한 줄 명시 | 같은 이름의 스캐너가 여러 개 있다 | M17 | §1.2, §19 |
| 구현 순서에서 테스트넷·체인 확인 Gateway를 앞으로, compose V2 이전 단계 추가 | 체인이 필요한 장면을 먼저 실증하기 위해 | M10, M11, M13 | §16 |
| GitHub 기본 브랜치를 `master/main`으로 변경(2026-10-11 완료) | 심사자가 오래된 README/코드를 보게 된다 | M16 | §14.1 |
| 4회차(컨트랙트 상세) 준비: gas·키 교체·정책 버전 관리 | 다음 멘토링 주제 | M18 | §9.5, §16, [대응 문서 4회차 준비](mentoring-2026-10-response.md#4회차-준비) |

**이번 변경으로 생긴 것과 아직 아닌 것.** 이번 변경은 위 장면을 **로컬 EVM(Ganache, LOCAL_EVM)** 에서 자동 통합 테스트와 측정 스크립트로 구현한다(§14.1). 스캐너는 실제 Docker 검사가 아니라 명시적인 **REPORT FIXTURE 테스트 대역**이다. Base Sepolia 반복, 실제 AI 연결, compose·대시보드의 V2 두 회사 스택은 **아직 하지 않았다**(다음 단계, §16).

ADR 목록: [ADR-003 검증자 컨소시엄](adr-003-validator-consortium.md) · [ADR-004 블록체인 필요 장면](adr-004-blockchain-necessity-scene.md) · [ADR-005 최종 데모 경로](adr-005-capstone-demo-path.md) · [ADR-006 재검사 정책](adr-006-gateway-recheck-policy.md) · [ADR-007 owner 권한 운영](adr-007-registry-owner-governance.md). 기존 [ADR-001](adr-001-mvp-boundary.md), [ADR-002](adr-002-ai-chain-boundary.md)는 그대로 유효하다.

---

## 0B. 기존 문서와의 관계 (v2.0에서 유지)

### 0B.1 무엇을 계승하고 무엇을 바꾸는가

| 원본의 요소 | 최종 결정 |
|---|---|
| 정확한 artifact와 Tool Surface 고정 | 유지. 실제 실행 이미지·의존성·정책 결합까지 기존 구현 재사용 |
| Static + AI + Sandbox | 유지. 지원 프로필 안에서 검사하며 완전한 악성코드 탐지를 주장하지 않음 |
| EIP-712·2-of-3·온체인 폐기 | 유지. 단일 팀의 3개 키/프로세스라는 실증 경계 표시 |
| Gateway의 실행 전 차단·drift 차단 | 유지. 실행 전 검사와 실행 후 표면 검사를 구분 |
| 실제 Agent·공개 테스트넷·두 Gateway | 모두 필수로 통일 |
| 정상 서명된 악성 업데이트 | synthetic 게시자 서명 데모를 필수로 확정 |
| 정상 메일 발송 시나리오 | 기존 `list_messages` 기반 **합성 메일 조회**로 변경 |
| npm/tarball/OCI 전체 필수 | Node npm/tarball 주력. 기존 제한형 OCI는 선택 유지 |
| SBOM·diff | 기존 최소 의존성 목록·변경점 재사용. 범용 SBOM 플랫폼 개발 없음 |
| DLQ·retry·멱등성 | 핵심 작업 경로의 기본 동작은 필수. stage별 분산 큐는 제외 |
| 캐시·appeal·receipt·관측성 고도화 | 구현된 것은 보존하되 추가 확장으로 완료를 지연하지 않음 |
| 운영 규모·PITR·다기관·멀티체인·TEE | 장기 Roadmap. 캡스톤 미완료 항목으로 세지 않음 |
| (v2.1) 운영사를 믿지 않는 회사의 집행 | 필수로 추가(CAP2-308). 다기관 실제 운영 자체는 여전히 Roadmap |

### 0B.2 우선순위의 단일 기준

- **P0:** §5의 41개 검수 단위(v2.0의 40개 + v2.1 신규 CAP2-308). 각 행에 연결된 본문 조건과 증거까지 충족해야 완료다.
- **P1:** §2.3의 선택 기능. 없다고 P0 완료를 막지 않는다. 활성화했다면 안전성 회귀 검사는 필요하다.
- **Roadmap:** §20의 범위. 이번 캡스톤에서 신규 구현하지 않는다.
- 본문·시연·일정에서 우선순위를 임의로 다시 정하지 않는다. 변경할 때는 §5와 변경 기록을 함께 수정한다.
- 기존 `FR-*`, v1.0의 `CAP-FR-*`, 이 문서의 `CAP2-*`는 서로 다른 요구사항 체계다. §21에 매핑한다.
- 기존 70% 및 18.56%는 2026-09-19의 **다른 분모**에 대한 역사적 감사값이다. 이 문서의 완료율로 옮겨 쓰지 않는다.
- 41개는 **신규 기능 41개가 아니라 묶어서 검수할 41개 단위**다. 이미 존재하는 기능을 다시 만들라는 뜻이 아니다. v2.0 기준 40개로 계산한 값과 v2.1 기준 41개로 계산한 값을 섞지 않는다.

캡스톤 범위 충돌은 이 문서를 기준으로 정리하되, 기존 `AGENTS.md`와 협업 규칙의 보안·파일 소유권·리뷰 원칙은 유지한다. 원본 전체 구현 계획은 장기 제품 계획으로 보존한다. 프로젝트의 기존 자동 목표·작업 상태는 별도이며 이 문서가 이를 자동 변경하지 않는다.

---

## 1. 문제와 최종 목표

### 1.1 처음 보는 사람을 위한 설명

AI는 메일·파일·DB 같은 외부 도구를 사용한다. MCP는 이런 도구를 연결하는 규격이다. 그런데 도구가 업데이트되면서 정상 기능 외에 몰래 파일을 읽거나 데이터를 전송할 수 있다.

MCPShield는 다음 네 질문에 답한다.

1. **무엇을 검사했나?** 정확한 프로그램과 실행 조건을 고정한다.
2. **무슨 위험을 발견했나?** 코드·설명·격리 실행에서 근거를 모은다.
3. **누가 판정했나?** 검증자들이 증거를 확인하고 판정을 서명한다.
4. **실제로 막았나?** Gateway가 현재 판정을 확인하고 실행을 거부한다.

### 1.2 캡스톤이 증명할 한 문장

> 같은 테스트용 게시자가 서명한 정상·악성 MCP를 구분하고, 악성 릴리스의 합성 비밀값 유출 증거를 검증하여 Base Sepolia에 폐기를 기록한 뒤, 두 Gateway가 그 정확한 릴리스의 실행을 차단한다. 정상 릴리스는 실제 AI Agent가 계속 사용할 수 있다. **운영사의 admission 서명 키가 장악되거나 운영사가 멈춰도, 자체 Control API로 체인을 확인하는 회사 B(Gateway B)는 폐기된 릴리스를 계속 차단한다.**

마지막 문장이 블록체인을 쓰는 이유를 직접 보여주는 장면이다(§9.1, CAP2-308). 운영사 API만 믿는 회사(Gateway A)는 같은 상황에서 (자기가 직접 보지 못한 폐기에 대해) 속거나 멈출 수 있으며, 이 차이를 대조군으로 함께 기록한다.

**차별점 한 줄.** MCP 서버 목록 사이트에는 비슷한 이름의 스캐너가 여럿 있다. MCPShield는 한 번 검사하고 끝나는 스캐너가 아니라 **업데이트마다 다시 검증하고, 실행 전에 Gateway에서 강제하며, 여러 기관의 판정을 공동 기록으로 묶는다**. 단, 이번 데모의 검증자 3개 키는 팀이 운영하며 다기관 운영은 설계 목표다(§9.2).

**이름·부제 안내.** 이름 `MCPShield`는 유지하되, 제출물·발표 표지에는 위 차별점이 드러나는 부제를 붙인다(§19의 부제 사용, 동명 연구와 구분).

### 1.3 최종 결과물의 수준

결과물은 **지원 범위가 명시된 보안 연구·통합 프로토타입**이다. 단순 클릭형 목업은 아니지만, 고객의 실제 비밀정보를 맡길 상용 보안 제품으로 선언하지 않는다.

- 검증된 릴리스도 특정 정책·환경·시간·시험 범위에서 승인된 것이다.
- 모든 악성 코드·모든 우회·모든 MCP를 안전하다고 보증하지 않는다.
- 핵심 성과는 기능 개수가 아니라 **증거 → 판정 → 공유 → 실제 집행**의 연결과 측정이다.

---

## 2. 범위 동결

### 2.1 지원 프로필

| 항목 | P0 지원 범위 |
|---|---|
| 패키지 | 허용한 출처의 exact npm 버전 또는 tarball. 악성 fixture는 공개 npm에 배포하지 않음 |
| 런타임 | 기존 prepared Node 프로필, Linux/Docker. 실행 이미지·Node 버전·플랫폼 고정 |
| MCP | stdio 우선. SDK/프로토콜 버전은 lockfile과 release manifest에 기록 |
| 정상 업무 | `list_messages`로 합성 메일 목록 조회. Gmail 인증·실제 발송·실제 고객 데이터 없음 |
| 실행 권한 | 기존 제한형 network-none 실행 정책을 주력으로 유지 |
| 관찰 환경 | 별도 격리 환경에서 synthetic canary와 허용된 내부 sink만 사용 |
| 정책 | 기존 버전·hash 기반 정책. 임의 코드 실행 권한을 API 입력으로 받지 않음 |
| 검증자 | 서로 다른 3개 키·프로세스. 조직적으로 독립된 기관이라는 주장 없음. 데모에서는 **팀이 3개 키를 모두 운영**함을 공개. 설계 모델은 “쓰는 회사가 곧 검증자” 컨소시엄([ADR-003](adr-003-validator-consortium.md)) |
| Gateway | 서로 다른 2개 프로세스와 분리된 상태/캐시. 같은 호스트여도 별도 프로세스로 표시. **판정 조회 경로도 분리**: A=운영사 Control API, B=회사 B 자체 Control API(§4.1, [ADR-004](adr-004-blockchain-necessity-scene.md)) |
| 실제 AI | 하나의 실제 모델 기반 Agent. 기존 harness/SDK 연결 재사용을 우선 |
| 체인 | 로컬 EVM으로 회귀 검사, Base Sepolia로 공개 실증. 컨트랙트는 **ReleaseRegistryV2 단일**(V1은 레거시·확장, §2.4) |
| DB/큐 | 기존 SQL 저장소·작업 큐. 통합 실증은 PostgreSQL 한 인스턴스; 빠른 로컬 개발은 기존 SQLite 허용. 운영사 비신뢰 장면 하네스는 회사별로 분리된 SQLite(운영사·회사 B, 장악 장면의 공격자 인스턴스는 별도 SQLite)를 사용(판정 상태는 DB가 아니라 체인에서 읽음, §9.1) |
| 외부 체험 | 기존 `/try`, `/mcp` 합성 데모 보존. 임의 패키지를 공개 URL에서 실행하는 서비스로 바꾸지 않음 |

지원 조건을 벗어난 native addon, 임의 외부 통신, 다른 언어·플랫폼 등은 이유와 함께 미지원/불완전으로 처리한다. 형식을 읽을 수 있다는 사실과 안전한 실행을 승인할 수 있다는 사실은 다르다.

### 2.2 이번에 하지 않는 기능 추가

- 실제 Gmail·Slack·CRM 로그인/발송/고객 DB 연결.
- 새 대시보드 프레임워크·새 Gateway·새 컨트랙트 체계로 전면 재작성.
- 임의 npm/OCI에 대한 범용 실행 허가.
- Redis·Kafka·RabbitMQ·Nginx를 기술 스택 목록을 늘리기 위해 도입.
- 모든 AI provider·모든 MCP client·모든 OS 대응.
- 실제 고객 운영·24시간 감시·대규모 트래픽·상용 SLA 보장.

### 2.3 P1 — 기존 구현 보존·선택 시연

| 선택 항목 | 재사용 원칙 | 확장하지 않을 경계 |
|---|---|---|
| 제한형 OCI | 기존 통합된 프로필과 테스트만 사용 | 미통합 scoped OCI를 이번 완료의 필수로 만들지 않음 |
| signed local cache / balanced mode | 기존 서명·만료·폐기 회귀 검사 유지 | P0 strict 모드에 장애 시 허용을 추가하지 않음 |
| appeal/rescan | 기존 화면·API 유지 | 승인 상태를 운영자가 강제로 복구하는 우회 추가 금지 |
| action receipt anchor | 기존 코드·검증 자료 보존 | 모든 호출을 온체인 기록하도록 확장하지 않음 |
| 고급 SBOM·취약점·license 분석 | 기존 출력을 활용 | 범용 SBOM/공급망 관리 서비스 개발 금지 |
| reorg recovery·DB backup smoke | 기존 검증을 재사용 | 장기 복구훈련·PITR·다중 지역 검증으로 확장하지 않음 |
| Grafana·OTel 운영 화면 | 기존 패널을 선택 사용 | 발표를 위해 기업 운영실 수준 UI 재작성 금지 |
| 타사 상용 Agent 추가 연동 | 주력 Agent 완료 후 설정으로 가능한 것만 | 제품별 plugin/인증 플랫폼 새 개발 금지 |

기존 안전 장치는 P1로 분류됐다는 이유로 삭제하거나 약화하지 않는다. P1 고장은 노출 경로를 제한하거나 비활성화하고 공개한다. P0가 이를 의존하면 해당 의존성의 안전성은 P0 검수에 포함된다.

### 2.4 본선 경로와 확장 (v2.1)

저장소에는 V1/V2 컨트랙트, 여러 admission 경로, break-glass, receipt anchoring, OCI, Streamable HTTP, PostgreSQL 전환 작업이 함께 있다. 지우지 않는다. 대신 **최종 데모가 지나가는 경로 하나**를 고정하고 나머지는 “확장”으로 표시한다([ADR-005](adr-005-capstone-demo-path.md)).

**본선 경로 — 최종 데모·P0 검수가 지나가는 길**

| 항목 | 고정값 |
|---|---|
| 브랜치 | `master/main` (GitHub 기본 브랜치, 2026-10-11 변경) |
| 컨트랙트 | `ReleaseRegistryV2` + `ValidatorRegistry` + `PolicyRegistry` 단일 세트 |
| 검증자 | 3개 키, 고유 2-of-3 정족수, 1개 재확인 가능한 긴급 증거로 임시 격리 |
| 실행 판정 | Gateway 서명 `/v1` admission 모드(`POST /v1/admission/check`의 서명 snapshot 검증) |
| Gateway A | 회사 A. 운영사가 호스팅하는 Control API에 묻고, 운영사 서명 키로 응답을 검증 |
| Gateway B | 회사 B. 회사 B가 직접 운영하는 Control API(자체 DB·자체 Ed25519 서명 키·자체 체인 조회)에 묻고, 회사 B 키만 고정. 운영사에 연결하지 않음 |
| 재검사 | 도구 호출마다 승인 상태 재확인(strict 기본, [ADR-006](adr-006-gateway-recheck-policy.md)) |
| 체인 | 로컬 EVM(Ganache)으로 자동 회귀 → Base Sepolia로 공개 반복(다음 단계) |

**확장 — 코드는 보존하되 최종 데모 경로의 전제 조건이 아님**

| 확장 항목 | 현재 상태 | 비고 |
|---|---|---|
| V1 `ReleaseRegistry`와 레거시 무서명 `/api` 경로 | 현재 기본 `docker-compose` 가 배포·사용 | compose를 V2 두 회사 스택으로 옮기는 것이 다음 단계(§16) |
| 조직 indexer 폴백·Gateway 직접 RPC 폴백 등 추가 admission 경로 | 코드 존재, 환경변수로만 켜짐 | 본선의 1차 조회 경로가 아님. 장애 시 폴백으로만 설명 |
| break-glass 긴급 실행 | 로컬 stdio 전용 기능으로 보존 | 데모 경로에서 제외. 승인 상태를 우회 복구하는 용도로 쓰지 않음 |
| action receipt anchoring | 코드·검증 자료 존재 | §2.3 P1과 동일 |
| 제한형 OCI | 기존 통합 프로필 | §2.3 P1과 동일 |
| Streamable HTTP 원격 데모(`/mcp`, `/try`) | 합성 데모로 보존 | 본선은 stdio 우선(§2.1) |
| PostgreSQL 전환 | 진행 중인 작업 보존 | 본선 장면의 판정 근거가 아님(판정은 체인에서 읽음) |
| signed local cache / balanced 모드 | 코드·회귀 검사 존재 | 장애 시 읽기 전용 호출 처리 측정(CAP2-504 (c))과, strict 모드에서 같은 캐시 파일의 폐기 기록(`.revoked`)을 Gateway A의 로컬 폐기 기록으로 쓰는 장면 ③·④에 사용. 캐시로는 쓰기를 허용하지 않음 |

발표·화면·문서에서 확장 항목을 본선 결과처럼 섞어 보여주지 않는다. 확장 항목을 시연할 때는 “확장”이라고 표시한다.

---

## 3. 기존 구현 최대 재사용 지도

### 3.1 변경 분류

- **R — 그대로 재사용:** 파일·인터페이스·구조 유지. 설정 및 동일 버전 테스트로 확인.
- **C — 연결/설정 보완:** 기존 모듈의 실제 입력·서명·체인·UI를 연결.
- **F — 버그 수정/재검증:** 실패 원인을 좁혀 기존 공통 함수에서 수정.
- **N — 최소 신규 산출물:** 없는 fixture·평가 표본·증거 manifest만 추가.

이 분류는 작업 방식이지 완료 판정이 아니다. 코드가 존재해도 검증 증거가 없으면 완료로 표시하지 않는다.

### 3.2 코드·산출물별 지도

| 영역 | 현재 사용할 위치 | 방식 | 필요한 보완 | 하지 않을 일 |
|---|---|---|---|---|
| Resolver/closure/runtime | `services/resolver/src/`, `services/scanner/src/prepared-*` | R/F | 고정 출처·closure·실행 이미지 결합 회귀 검사 | 새 package manager/설치기 작성 |
| 식별자·정책 | `packages/contracts-sdk/src/v2-identity.mjs`, `docs/interface-contract.md` | R | 실제 schema와 명세 일치 확인 | 새 releaseId 또는 ABI 설계 |
| Static/AI/Sandbox | `services/scanner/src/`, `services/exfil-sink/` | R/F/C | scoped-v2 실패 원인, 실제 provider·권한·probe 관찰 연결 | 새 분석 엔진/격리 플랫폼 작성 |
| 정상·악성 시나리오 | `demo/fixtures/mail-mcp-1.0.0`, `mail-mcp-1.0.1`, `probe-mail-mcp` | R/F | 조회 시나리오·지원 실행 정책 일치 | 실제 메일 서비스 도입 |
| 게시자 서명 | 기존 crypto/fixture/digest 구조 | N | 테스트용 서명 manifest와 검증·변조 검사 | PKI·Sigstore 서비스 새 구축 |
| API/작업 큐 | `apps/api/src/control-*`, `preparation-*`, `chain-outbox.ts` | R/F | 핵심 작업의 멱등성·실패 상한·DLQ 검증 | 큐 브로커 교체 |
| 컨트랙트 | `contracts/src/ReleaseRegistryV2.sol`, 기존 registry들 | R/C | 기존 ABI로 테스트넷 배포·source verification | 새 토큰·proxy·DAO 도입 |
| Validator/Indexer | `apps/validator/src/`, `apps/indexer/src/v2-indexer.ts` | R/F/C | 각 키의 독립 검증, 실제 chain event 반영 | 세 복사 서명으로 검증 대체 |
| Gateway | `apps/gateway/src/`, 기존 prepared·signed-admission·protocol guard | R/F/C | 실제 Agent 연결, 같은 identity의 A/B 차단 | 새 프록시를 옆에 중복 구현 |
| Dashboard | `apps/dashboard/components/operations-console.tsx`, `release-workflow.tsx`, `evidence-view.tsx` | R/C | 기존 패널을 발표 순서로 배치·한글 설명·링크 확인 | 전체 디자인/라우팅 재작성 |
| 평가 | `benchmarks/evaluate.mjs`, `agent-mcp-harness.mjs`, `evaluate-ai-mcp.mjs` | R/C/N | 독립 표본·5비교군·실제 Gateway 기반 보호 경로 | 평가 framework 신규 도입 |
| 운영사 비신뢰 장면 (v2.1) | `tests/integration/consortium-scene.ts`, `consortium-scene.test.ts`, `scripts/ops/evaluate-consortium-scene.ts` | N | 기존 `apps/api` 두 인스턴스·기존 Gateway·V2 조회기를 그대로 묶는 하네스. 테스트넷 반복과 compose 연결은 다음 단계 | 장면 전용 판정 함수·별도 Gateway 작성 |
| CI/배포 구성 | `.github/workflows/frontend-gateway-devops.yml`, 기존 Compose·Dockerfile | R/F | P0 실행·SKIP 경계·동일 SHA 증거 확인 | 새 CI 시스템 구축 |
| 문서/발표 | 기존 `docs/pitch/`, `docs/guide/`, 데모·운영 문서 | R/C/N | 범위 문구 수정, 실제 PPT/PDF·영상·재현 기록 | 기존 자료 전부 폐기 |

### 3.3 특히 재사용할 때 주의할 것

1. 기존 `/api`의 `name@version`과 `/v1`의 bytes32 release ID는 호환 식별자가 아니다. 데모 문자열을 V2 승인에 넣지 않는다.
2. 현재 prepared 정상 E2E는 `list_messages` 합성 조회다. 메일 발송 기능이 있다고 바꾸어 설명하지 않는다.
3. 기존 Agent 평가 실행 파일의 `SCANNER_POLICY_NOT_CHAIN` 결과는 Full MCPShield ASR가 아니다. harness는 재사용하되 실제 Gateway 집행 경로로 연결해야 한다.
4. 기존 SDK client smoke는 MCP 통신 증거다. 실제 LLM의 도구 선택·호출 증거를 대신하지 않는다.
5. 기존 MOCK/replay의 publisher `VALID` 표시는 실제 게시자 서명 검증이 아니다.
6. 별도 worktree의 `8c13b9c` OCI checkpoint는 자동으로 통합하지 않는다. P0 Node 경로의 선행조건이 아니다.
7. 기능 경로는 유지하고 같은 guard·schema·hash 함수를 사용한다. 테스트를 맞추기 위한 별도 데모 판정 함수를 만들지 않는다.
8. (v2.1) 현재 기본 `docker-compose`는 V1을 배포하고 두 Gateway를 레거시 무서명 `/api` 경로로 띄운다. 두 Gateway가 같은 운영사 API를 보고 서명 검증 설정이 없으므로, compose 화면을 본선 경로(V2·서명 `/v1`·Gateway별 조회 경로 분리)의 증거로 쓰지 않는다. 서명 검증·조직 indexer·직접 체인 조회 코드는 존재하지만 기본값으로 꺼져 있다.

### 3.4 재작성 방지 심사

새 코드 작성 전 PR에 다음 세 문장을 적는다.

- 기존 어느 모듈을 재사용하는가?
- 기존 모듈의 설정·연결·짧은 수정으로 해결되지 않는 이유는 무엇인가?
- 새 부분을 검증하는 가장 작은 재현 검사는 무엇인가?

코드량을 줄이기 위해 보안 검사를 삭제하지 않는다. 반대로 일반화·새 추상화·새 서비스를 캡스톤 완료 조건에 추가하지 않는다.

---

## 4. 전체 아키텍처와 Workflow

### 4.1 세 영역과 두 가지 흐름 (v2.1에서 다시 그림)

세 영역(검사 Control Plane / 공동 상태 Trust Plane / 실제 집행 Execution Plane)의 구분은 그대로다. 이 구조는 컨테이너 이미지 서명과 Kubernetes admission controller를 함께 쓰는 공급망 보안 패턴과 닮았다. 다만 v2.0은 성격이 다른 두 흐름을 하나의 파이프라인처럼 그렸다. v2.1은 **검증 흐름**과 **실행 통제 흐름**을 나누어 그리고, Gateway가 판정을 어디서 조회하는지 별도 그림으로 보인다.

| 구분 | 흐름 1. 검증 흐름 | 흐름 2. 실행 통제 흐름 |
|---|---|---|
| 언제 도는가 | 새 릴리스(새 source·실행 조건·정책 조합)당 1회 | 도구 호출(`tools/call`)마다 |
| 구조 | 파이프-앤-필터: 각 단계가 걸러낸 증거를 다음 단계로 넘김 | 프록시·인터셉터: Agent와 MCP 사이에서 호출을 가로채 확인 |
| 사용자가 기다리나 | 아니다. 실행 경로 밖에서 돈다 | 그렇다. 호출마다 확인 시간이 더해진다 |
| 주된 비용 | 스캔 시간(Docker 격리 실행·AI 호출 비용), 검증자 서명, 체인 거래 gas와 확인 대기 | 호출당 admission 확인 지연, 서명 검증, (HTTP serve 모드) 호출마다 재스냅샷·해싱·자식 프로세스 시작 |
| 측정 위치 | §12.5 Scan latency, Chain cost/time | §12.5 호출당 추가 지연·전파 시간·장애 시 처리(CAP2-504 (a)(b)(c)) |
| 실패하면 | 검사 불완전 → VERIFIED를 만들지 않음 | 상태 불명 → strict 모드는 차단(fail-closed) |

**흐름 1 — 검증 흐름 (릴리스당 1회, 파이프-앤-필터, 실행 경로 밖)**

```text
[Control Plane]
등록 → Resolver → source/closure/runtime 고정
                    ├─ Static / version diff
                    ├─ 실제 AI 의미 분석 / 제한된 probe
                    └─ 격리 Sandbox / canary / synthetic sink
                                      ↓
                          Evidence + Policy 판정
                                      ↓
[Trust Plane]
Validator A / B / C 각각 증거 확인 → EIP-712 서명 → 고유 2-of-3
  (재확인 가능한 긴급 증거 1건은 검증자가 체인에 직접 임시 격리 가능)
                                      ↓
              ReleaseRegistryV2  (로컬 EVM 회귀 → Base Sepolia 공개 실증)
              상태: VERIFIED / QUARANTINED / REVOKED / EXPIRED
                                      ↓
              Indexer → DB projection → 화면·이력 조회 (실행 판정의 근거 아님)
```

**흐름 2 — 실행 통제 흐름 (호출마다, 프록시·인터셉터, 사용자가 기다리는 경로)**

```text
[Execution Plane]
실제 LLM Agent → MCP Client → Gateway → (ALLOW일 때만) 승인된 제한형 MCP
                                 │
                                 ├─ tools/call마다 admission 확인 → 서명된 판정 수신
                                 │     (어디에 묻는지는 아래 그림 3)
                                 │
                                 └─ REVOKED / QUARANTINED / 변조 / 상태불명 / 만료
                                       → 이번 호출 차단 (후보 실행·전달 없음)
```

**그림 3 — Gateway별 판정 조회 경로**

```text
회사 A (운영사 API를 신뢰하는 편의 모드 · 대조군)
  Gateway A → 운영사 Control API(운영사 서명 키) → 체인 ReleaseRegistryV2
  · 운영사 API는 요청마다 체인을 읽고 그 결과에 서명한다.
  · Gateway A는 운영사 서명만 검증하고 체인을 스스로 다시 읽지 않는다.

회사 B (운영사를 믿지 않는 자체 확인 모드)
  Gateway B → 회사 B 자체 Control API(회사 B 서명 키, 자체 DB) → 체인 ReleaseRegistryV2
  · 회사 B API가 같은 컨트랙트를 직접 읽고 회사 B 키로 서명한다.
  · Gateway B는 회사 B 키만 고정하고 운영사에 연결하지 않는다.
```

두 경로 모두 마지막 근거는 같은 체인이다. 차이는 **누가 체인을 읽고 서명하느냐**다. 운영사가 멈추면 A는 판정을 받지 못해 차단(업무 중단)되고 B는 계속 동작한다. 운영사의 서명 권한이 장악되면 A는 자기가 직접 보지 못한 폐기에 대해 위조된 ALLOW를 받아들일 수 있지만(이미 본 폐기는 같은 프로세스의 메모리 기록이나 로컬 폐기 기록 파일이 있으면 거부), B는 체인의 REVOKED를 그대로 본다. 이 차이가 CAP2-308 장면이다(§9.1, §10.3). 현재 장면 하네스에서는 두 회사가 같은 로컬 RPC를 쓰며, 실제 운영에서는 회사별 자체 노드 또는 여러 RPC 제공자를 쓰는 것을 전제로 한다(§20).

Dashboard는 이 흐름을 보여주는 소비자다. Dashboard의 색상이나 상태 버튼이 실행 허가의 근거가 아니다.

### 4.2 정상 릴리스

1. 허용된 정상 source를 수집하고 게시자 서명을 검증한다.
2. 기존 resolver/preparation으로 의존성과 실행 대상을 고정한다.
3. Static/AI/Sandbox 필수 검사와 정책 확인을 완료한다.
4. 검증자 둘 이상이 해당 identity·policy·evidence를 확인하고 PASS 서명한다.
5. 컨트랙트 상태·Indexer projection·유효한 admission 증거가 연결된다.
6. 실제 Agent가 Gateway를 통해 `list_messages`를 호출한다.
7. 합성 메일 결과와 성공한 호출 trace를 기록한다.

### 4.3 악성 업데이트

1. 동일 테스트 게시자가 다른 bytes의 악성 업데이트에도 정상 서명한다.
2. 격리된 OFF 실험에서 합성 유출을 관측한다. 실제 비밀은 넣지 않는다.
3. 검사 경로에서 동일 source의 유출 증거와 승인 대상 identity 결합을 확인한다.
4. 독립 검증한 critical evidence를 근거로 FAIL 판정을 수집한다.
5. 1개 유효한 긴급 증거는 임시 격리, 2-of-3 FAIL은 최종 폐기로 처리한다.
6. Base Sepolia 거래와 이벤트를 Indexer가 반영한다.
7. A/B Gateway가 각자의 판정 조회 경로(§4.1 그림 3)로 같은 폐기 identity를 확인하고 거부한다. 후보 코드가 시작되지 않았음을 측정한다.

### 4.4 무거운 검사는 매 호출마다 다시 하지 않는다 — 승인 상태 확인은 매 호출

무거운 분석(흐름 1)은 새 source·실행 조건·정책 조합을 대상으로 한다. 실행 경로(흐름 2)에서는 고정 identity와 유효한 최신 판정만 확인한다. **검사 1회가 영구 안전 인증을 뜻하지는 않는다.**

재검사 정책([ADR-006](adr-006-gateway-recheck-policy.md)):

- 기본값은 **도구 호출마다 승인 상태를 다시 확인(strict)** 하는 것이다. 현재 Gateway도 `tools/call`마다 재검사한다.
- 판정을 N초 동안 재사용하는 창은 측정값(§12.5)을 보고 나서만 정한다. 재사용 창을 두면 그 길이가 곧 **폐기된 릴리스가 계속 실행될 수 있는 최대 시간**이므로 반드시 함께 보고한다.
- 판정 서버 장애·판정 만료 시(조직 indexer·직접 RPC 폴백을 켜지 않은 본선 구성 기준): strict는 읽기·쓰기 모두 차단한다. balanced(확장)는 아직 유효한 서명 캐시(판정 발급 후 최대 30초)가 있을 때 **읽기 전용 호출만** 허용하고, 캐시로는 쓰기를 허용하지 않는다. 본선 기본값은 strict다. 폴백을 켜면 indexer의 새 서명 판정은 쓰기도, 직접 RPC는 strict에서도 읽기 전용 호출을 허용할 수 있다([ADR-006](adr-006-gateway-recheck-policy.md)).
- 읽기/쓰기 구분은 도구 선언(`readOnlyHint`, `destructiveHint`)을 따른다. 이 선언은 도구 표면 해시에 포함되므로 검증 뒤 몰래 바꾸면 차단된다. 그러나 처음부터 쓰기 도구를 읽기로 거짓 선언하는 것은 검사 단계에서 잡아야 하며, 선언만으로 위험도를 낮춰 주지 않는다는 §7.3 원칙은 그대로다.

---

## 5. P0 요구사항 — 유일한 필수 검수 목록

다음 41개 행이 완료율의 분모다(v2.0의 40개 + v2.1 신규 CAP2-308. 기존 ID는 바꾸지 않음). 각 행의 하위 조건은 AND다. N/A로 분모를 조용히 줄이거나 부분 구현에 0.5점을 주지 않는다. 요구 변경 시 문서 버전과 매핑을 갱신한다.

역할: S = Security·AI, B = Blockchain·Backend, F = Frontend·Gateway·운영, M = Main. 공동 역할이어도 PR 주 담당자는 한 명으로 정한다.

### 5.1 수집·식별 — 6개

| ID | 필수 결과 | 완료 증거 | 담당 |
|---|---|---|---|
| CAP2-001 | 허용된 Node npm exact/tarball을 수집하고 지원 프로필 밖 입력은 거부/미지원 표시 | mutable locator 고정·허용 출처·미지원 입력 테스트 | S |
| CAP2-002 | source bytes, dependency closure, 실행 이미지와 argv/환경/정책을 변경 불가능한 결합으로 고정 | 기존 descriptor·digest와 source/dependency/image 교체 거부 검사 | S/F |
| CAP2-003 | 전체 Tool Surface를 결정적으로 정규화·고정 | pagination 완결, 순서만 다른 동일 표면, description/schema/annotation 변경 검사 | S/F |
| CAP2-004 | 같은 테스트 게시자 키의 정상/악성 서명을 실제로 검증 | 두 서명 성공, bytes 변조·다른 키·서명 누락 거부, demo key 표시 | S |
| CAP2-005 | 출처·수집시각·게시자 검증 수준·정확한 비교 baseline 기록 | 동일 이름/버전의 다른 bytes와 pinned baseline 구분 자료 | S/B |
| CAP2-006 | 검사·검증자·Gateway가 같은 실행 identity와 policy를 사용 | 단계 사이 대상 교체·만료·v1/v2 증거 혼용 거부 통합 검사 | M |

### 5.2 분석·증거 — 8개

| ID | 필수 결과 | 완료 증거 | 담당 |
|---|---|---|---|
| CAP2-101 | description/schema·파일·process·egress·install script 위험 신호 및 최소 dependency diff | 공격/정상 fixture; 허용된 파일 읽기·통신은 자동 악성 아님을 검사 | S |
| CAP2-102 | 실제 모델의 schema 강제 의미 분석과 provider/model/prompt 출처 기록 | 실제 호출 기록, redacted input, schema 오류·주입·timeout 검사 | S |
| CAP2-103 | 기존 baseline 대비 의미·권한·도구 표면 변화 설명 | 정상 업데이트와 목적/권한 확대 사례, evidence span·근거 연결 | S |
| CAP2-104 | 미검증 코드와 보호 OFF 실험을 제한된 일회성 Docker 환경에서만 실행 | host secret/socket 접근 금지, egress·CPU/RAM/PID/시간 제한·정리 검사 | S |
| CAP2-105 | 지원 범위의 행동과 canary 유출을 관찰하고 identity-bound evidence 저장 | 내부 sink 증거, trace·hash/root 결합, 변조 거부, 비밀 마스킹 | S/B |
| CAP2-106 | 허용된 bounded probe를 실제 실행하고 입력·관찰 결과를 결합 | 생성안≠실행 결과 구분, tool/인자 허용 범위와 실제 실행 digest 검사 | S |
| CAP2-107 | PASS/FAIL/ABSTAIN과 검사 불완전·인프라 오류를 구분 | §8 판정표, AI 장애·강한 증거·불충분 증거 각각의 회귀 검사 | S/B |
| CAP2-108 | 분석 결과가 실행 조건·관찰 범위·한계를 명시하며 과장하지 않음 | Node 관찰 한계·미지원·coverage 누락 표시, 위조 COMPLETE/PASS 거부 | S/F |

### 5.3 공동 판정·체인 — 7개

| ID | 필수 결과 | 완료 증거 | 담당 |
|---|---|---|---|
| CAP2-201 | 기존 EIP-712가 identity·policy·evidence·verdict·기한·도메인에 결합 | signature recovery, 다른 체인/contract/policy/root·만료/nonce 재사용 거부 | B |
| CAP2-202 | 검증자 3개가 별도 키·프로세스로 증거를 각자 검증 | 검증자별 source/검증 기록, 변조된 API verdict 복사 서명 거부 | B/S |
| CAP2-203 | 고유 검증자 2-of-3 PASS/FAIL 정족수와 불일치 처리를 보장 | 중복·비활성 키·서로 다른 identity/policy·불일치 투표 테스트 | B |
| CAP2-204 | 격리 TTL·폐기 terminal·승인 만료·상태 우선순위를 준수 | §9 상태 전이 검사, REVOKED 복구 거부, 만료 후 자동 허용 없음 | B |
| CAP2-205 | Base Sepolia에 기존 컨트랙트를 배포하고 실제 정상/폐기 상태를 증명 | source/bytecode 확인, 계약 주소·safe/revoke tx·이벤트·검증자 manifest | B |
| CAP2-206 | 체인 이벤트가 인증된 projection과 두 Gateway 판정에 반영 | block/hash·관측시각·lag·중복/역순·재시작·stale 거부 검사 | B/F |
| CAP2-207 | 원문 증거·개인정보·비밀을 온체인에 넣지 않고 보고서 무결성을 검증 | 저장 필드 검토, off-chain report 변조 거부, 공개 산출물 secret 점검 | B/S |

### 5.4 Gateway·Agent — 8개

| ID | 필수 결과 | 완료 증거 | 담당 |
|---|---|---|---|
| CAP2-301 | 기존 MCP wrapper가 실제 client↔server 통신을 중계 | 선택 SDK/프로토콜의 정상 조회, framing·stderr 로그 검사 | F |
| CAP2-302 | 후보 실행 전에 exact bytes·승인·정책·기한을 확인 | 폐기/변조/불명확 릴리스의 후보 실행 start/spawn 0건과 양성 대조군 | F |
| CAP2-303 | 격리 시작 후 전체 tools/list 검증을 끝내기 전 tool 노출/호출을 차단 | runtime drift·pagination·미선언 tool 호출 거부, 세션 정리 검사 | F |
| CAP2-304 | 실행 중인 세션도 후속 호출에서 폐기·만료를 재검사 | 세션 유지 중 revoke 후 다음 tools/call 미전달; 검사/전달 경합 회귀 | F |
| CAP2-305 | strict 모드의 상태불명·stale·서명 오류는 허용하지 않음 | RPC/Indexer 장애·낡은 승인·잘못된 서명·명시적 거부의 fail-closed 검사 | F/B |
| CAP2-306 | 실제 LLM Agent 1종이 동일 Gateway를 통해 정상 도구를 사용 | 모델 선택→실제 tools/call→합성 결과 trace; SDK 스모크와 구분 | F/S |
| CAP2-307 | 두 독립 Gateway가 동일 release identity의 폐기를 집행. **A는 운영사 Control API의 서명 판정을 신뢰, B는 회사 B 자체 Control API(자체 DB·서명 키·체인 조회)의 서명 판정만 신뢰**(§4.1 그림 3) | A/B 프로세스·상태 저장소·서명 키·조회 경로 구분, 같은 chain tx 이후 각 차단 시각과 이유 | F/B |
| CAP2-308 | **운영사 비신뢰 집행**(v2.1 신규): 운영사의 admission 서명 권한이 장악되거나(위조된 VERIFIED/ALLOW 서명) 운영사가 멈춰도, 자기 회사(B) Control API로 체인을 확인하는 Gateway B는 REVOKED 릴리스를 계속 차단하고(거짓 ALLOW 0건), 운영사 중단 시 정상 릴리스 사용을 유지. 운영사 API를 신뢰하는 Gateway A의 결과(장악 시 폐기를 직접 보지 못한 A는 위조 ALLOW, 폐기를 이미 기록한 A는 로컬 기록으로 거부, 중단 시 fail-closed)는 **대조군**으로 함께 기록. MVP에서 운영사 API 프로세스 전체가 장악되면 owner 권한까지 넘어가 B도 정상 릴리스에서 fail-closed될 수 있음(서비스 거부, §9.5) | 컨소시엄 장면 테스트(`tests/integration/consortium-scene.test.ts`, LOCAL_EVM, REPORT FIXTURE 스캐너 대역) + 테스트넷(Base Sepolia) 반복. 각 장면의 체인 실제 상태와 A/B 판정·이유 대조 | M/B |

### 5.5 Backend·운영·산출물 — 7개

| ID | 필수 결과 | 완료 증거 | 담당 |
|---|---|---|---|
| CAP2-401 | 기존 SQL 큐의 비동기 실행·멱등성·제한 retry/backoff·DLQ | 중복·worker crash·timeout·chain 응답 유실에서 중복 반영/무한 재시도 없음 | B |
| CAP2-402 | 기존 입력 검증·권한 분리·비밀 분리를 핵심 경로에 적용 | 400/401/403/409 구분, 임의 경로/명령/키 입력 거부·권한 회귀 | B/F |
| CAP2-403 | 누가/언제/왜 판정했는지 추적하고 사용자에게 한 줄 이유 제공 | release/scan/validator/tx/admission 연결 로그와 화면·API 조회 재현 | B/F |
| CAP2-404 | 기존 Dashboard가 실제 증거 흐름을 한 화면/연결된 패널로 설명 | 브라우저 실제 조작, safe/bad·서명·evidence·vote·tx·A/B 차단 확인 | F |
| CAP2-405 | 선택한 RC SHA의 필수 CI와 Linux/Docker 통합 경로가 성공 | required gate 실제 실행·0 SKIP, 원인 미해결 실패 없음, 독립 리뷰 | M |
| CAP2-406 | 깨끗한 환경에서 문서대로 재현하고 local E2E 10회 연속 성공 | 버전/설정 manifest·명령·로그, 합성 replay 표시, 종료/정리 절차 | M/F |
| CAP2-407 | 최종 보고·PPT/PDF·영상과 코드·실험 증거를 같은 RC에 연결 | 열리는 실제 파일·Git SHA·Explorer·제한 사항·출처·링크 검수 | M |

### 5.6 평가 — 5개

| ID | 필수 결과 | 완료 증거 | 담당 |
|---|---|---|---|
| CAP2-501 | 개발셋과 분리한 최소 정상 20개·공격 20개 최종 표본 | label 근거·두 사람 검토·family 분리·출처/라이선스·dataset hash | S/M |
| CAP2-502 | Static / AI / Sandbox / Static+Sandbox / Full 5개 비교군 측정. **방법별 기여(Static·AI·Sandbox가 각각 무엇을 잡았는지)를 따로 표시** | 동일 고정 표본·방법별 적용 가능성·stage 재사용 여부·TP/FP/FN/TN/보류 원자료, 표본별 탐지 방법 표. 같은 예제 반복 결과는 재현성 증거로만 분류 | S |
| CAP2-503 | 실제 Agent의 OFF/ON 결과와 정상 업무 성공률을 함께 측정 | 실제 sink/action oracle, 동일 시나리오, §12 반복·분모·실패 기록 | S/F |
| CAP2-504 | scan/admission/revoke 전파·chain 비용/시간을 실제 측정. Gateway 실행 비용 3가지 포함: **(a)** Gateway 없이 직접 호출 대비 A/B 경유 시 `tools/call` 1회당 추가 지연, **(b)** 격리·폐기 거래 포함 시점부터 각 Gateway가 다음 호출을 막기까지 시간, **(c)** 판정 서버 중단·판정 만료 시 읽기/쓰기 도구 처리 | 환경·표본 수·시작/종료 정의·p50/p95·오류율·raw 결과. LOCAL_EVM과 Base Sepolia 값을 분리하고, 스캐너 실행 시간(예: 기존 “93ms”)을 Gateway 지연으로 쓰지 않음 | B/S |
| CAP2-505 | 재현 가능한 실험 보고와 과장 없는 결론 제공 | commit/model/prompt/policy/image/dataset/chain manifest, 불확실성·실패 포함 보고 | M |

---

## 6. 기술 스택과 책임 경계

새 기술 도입 목록이 아니라 **현재 저장소의 선택을 유지하는 기준**이다. 정확한 버전은 RC의 `package-lock.json`과 이미지 digest를 따른다.

| 역할 | 기존 기술 | 쉽게 말하면 |
|---|---|---|
| 화면·BFF | Next.js / React / TypeScript | 사용자가 작업을 요청하고 결과를 확인하는 창구 |
| API | Fastify / TypeScript, 기존 schema 검증 | 입력·권한·업무 순서를 검사하는 관리자 |
| DB·작업 큐 | PostgreSQL, 기존 SQL queue/outbox | 상태·작업·이력을 보관하는 장부와 대기열 |
| 분석·Resolver | Node.js, 기존 scanner·resolver | 정확한 프로그램을 확보하고 위험 근거를 찾는 검사기 |
| 격리 | 기존 Docker hardening·permission 설정 | 후보 프로그램을 제한된 실험실에서 실행 |
| MCP 연결 | 기존 MCP SDK·stdio Gateway | Agent와 도구 사이에서 실행 권한을 확인하는 문 |
| 공동 상태 | Solidity, ethers, 기존 V2 registry | 서명된 공동 판정과 폐기 이력을 공유 |
| 로컬 체인 | 기존 `chain:local` 및 EVM 테스트 | 외부 거래 없이 빠르게 반복 검사 |
| 실증 체인 | Base Sepolia | 외부에서 확인할 수 있는 테스트넷 증빙 |
| 관측 | 기존 구조화 로그·OTel, 선택 Grafana | 실패 원인·흐름·시간을 찾는 기록 |
| 자동 검증 | 기존 GitHub Actions·Docker Compose | 코드 변경 시 기존 흐름이 깨지는지 검사 |

API는 검증자 키를 소유하지 않는다. 후보 컨테이너는 모델 키·검증자 키·host Docker socket을 받지 않는다. Docker를 제어하는 신뢰된 worker와 실행되는 미검증 컨테이너를 구분한다.

### 6.1 API와 데이터 모델은 교체하지 않는다

기존 `/api`는 이전 데모 호환성을 위해 보존한다. 확장 기능은 기존 `/v1`과 Dashboard BFF를 사용한다. 정식 요청 schema와 전체 필드는 [기존 인터페이스](interface-contract.md), [API README](../apps/api/README.md)를 따른다.

| 작업 | 재사용할 경로/흐름 |
|---|---|
| source 등록 | `POST /v1/releases/resolve` |
| 실행 대상 준비 | `POST /v1/releases/:sourceReleaseId/prepare` → preparation worker |
| scan | `POST /v1/scans`, `GET /v1/scans/:id` |
| 증거 | `GET /v1/scans/:id/evidence` — 기존 권한 검증 유지 |
| 검증 서명 | 기존 attestation template 검증 → `/v1/validator/attestations` |
| 실행 판정 | `POST /v1/admission/check` — signed snapshot 검증 |
| 이력/상태 | `/v1/releases/:id/history`, `/v1/events`, 인증된 `/v1/health` |
| 화면 | 기존 `/console`, 기존 Dashboard·BFF |

최소 데이터 연결은 source release → prepared release → scan attempt → evidence root → validator attestation → chain action/tx → indexed state → Gateway decision이다. 이름·버전 문자열로만 join하지 않는다. 운영 metadata는 DB, raw evidence는 기존 보호된 off-chain 저장소, 체인에는 commitment와 상태를 둔다.

---

## 7. Identity·게시자 서명·실행 대상

### 7.1 식별자의 정확한 의미

기존 V2 release ID 계산을 그대로 사용한다.

```text
releaseId = keccak256(abi.encode(
  toolId, artifactDigest, manifestDigest, toolSurfaceDigest
))
```

source의 원본 bytes digest와 prepared runtime의 descriptor digest는 다른 값일 수 있다. 무엇을 해시했는지 필드/프로필에 명시하고 서로 바꿔 쓰지 않는다. dependency closure, 고정 image/config, argv·환경·플랫폼·실행 정책은 기존 descriptor/manifest 결합 규칙을 따른다. policyHash는 판정에 별도로 결합하고 정책별 승인 유효성을 검증한다.

프로젝트명을 최종 식별자로 사용하거나, `latest`를 기록만 해놓고 실행 시 다시 resolve하지 않는다. 검사 후 실행 전 바꿔치기를 거부하고 승인 대상은 읽기 전용·고정 실행 조건으로 사용한다.

### 7.2 게시자 서명의 최소 구현

- 동일한 **데모 전용 게시자 키**로 safe/bad 원본 artifact의 digest와 식별 metadata를 서명한다.
- 원본 source 서명과 derived runtime의 연결은 기존 source→descriptor 관계로 검증한다.
- 표준 crypto/기존 의존성으로 작은 서명·검증 절차를 만든다. 새로운 인증기관 서버는 만들지 않는다.
- verifier는 설정된 공개키·원본 digest를 검사한다. fixture가 스스로 제공한 공개키만 믿지 않는다.
- 두 버전 서명 성공, 변조 실패, 다른 키 실패, 서명 누락 실패를 각각 기록한다.
- 테스트 키와 공개 signature를 쓸 수 있으나, 실제 계정/운영키는 fixture·저장소에 넣지 않는다.
- UI에 `DEMO_PUBLISHER_SIGNATURE_VALID`처럼 의미를 설명한다. 이것이 npm 공식 provenance라는 주장은 하지 않는다.

서명 manifest schema·알고리즘은 구현 시 기존 crypto 사용처를 확인해 하나로 동결한다. 서명 검증 성공은 게시자와 bytes의 결합이지 안전한 행동의 증명이 아니다.

### 7.3 Tool Surface

name·description·input/output schema·annotations를 기존 canonicalizer로 처리한다. 페이지를 모두 읽기 전 COMPLETE가 아니다. annotations도 검사 대상 데이터이며 스스로 read-only라고 선언했다고 권한을 낮춰 주지 않는다. 지원하지 않는 schema·무한 pagination·과대 응답은 제한하고 거부한다.

---

## 8. 분석·정책·안전한 실험

### 8.1 각 분석기의 역할

| 분석기 | 맡길 일 | 맡기지 않을 일 |
|---|---|---|
| Static | 민감 경로·shell·egress·설치 스크립트·메타데이터 위험 신호 | 문자열이 있다는 이유만으로 악성 확정 |
| AI | 목적/권한 불일치, 숨은 지시, 의미 변화, 제한된 시험 후보 | 해시·서명·체인 상태 판정, 단독 영구 폐기 |
| Sandbox | 지원 프로필의 실제 행동·도구 호출·sink 도달 관찰 | 모든 syscall/언어/시간 지연 공격의 완전 관찰 주장 |
| Policy | 신뢰할 수 있는 증거·완결성·버전을 기존 규칙으로 결합 | 모델 confidence만으로 승인/폐기 |

실제 LLM 호출은 redacted·허가된 최소 입력만 사용한다. package/description은 명령이 아니라 신뢰할 수 없는 데이터다. 분석 모델에 임의 shell/network 권한을 부여하지 않는다. 구조화 출력·길이·시간·비용·tool/인자 제한과 기존 출처 결합을 유지한다. 기존 Analyzer/Critic이 지원 경로의 검증 조건이면 재사용하고, 별도의 multi-model 플랫폼으로 확장하지 않는다.

### 8.2 판정표 — 오류와 악성을 구분

| 조건 | scan/validator 의미 | 실행 의미 |
|---|---|---|
| 올바른 identity에 귀속된 독립 검증 가능한 critical 증거 | 정책 조건을 충족하면 FAIL; AI 불능 자체가 이 증거를 지우지는 않음 | 격리/폐기 판정과 현재 상태에 따라 BLOCK |
| AI만 의심, 재현 가능한 critical 없음 | WARN/REVIEW/ABSTAIN; AI 단독 영구 폐기 금지 | 승인 조건 미충족이면 BLOCK, 악성 확정이라고 표시하지 않음 |
| 필수 분석·binding·관찰이 불완전하고 확정 증거 없음 | ABSTAIN/INCOMPLETE | VERIFIED 생성 금지 |
| 필수 검사 완료, critical 없음, 정책 충족 | PASS 후보; quorum은 별도 | 유효한 승인·정족수·현재 상태까지 충족해야 ALLOW |
| hash 변조·서명 오류·REVOKED·만료·상태불명 | source/authority/상태별 구체적인 이유 | BLOCK. 모두를 `악성코드 탐지`로 세지 않음 |

출처나 실행 대상 결합이 깨진 보고서의 canary 문구만 보고 FAIL로 확정하지 않는다. 신뢰 경계 검증이 먼저다. native scoped-v2의 `ABSTAIN` 문제는 이 경계를 복구하는 버그 수정 대상이지, 모든 ABSTAIN을 FAIL로 바꾸는 작업이 아니다.

### 8.3 보호 OFF/ON 실험의 안전성

**OFF는 admission 보호를 적용하지 않는 대조군이지 host 보호 해제를 뜻하지 않는다.**

- OFF/ON 모두 후보는 격리 환경에서만 실행한다.
- 실제 credential·SSH key·고객 파일·wallet 대신 명확한 dummy canary만 사용한다.
- 관찰용 네트워크는 합성 sink/허용 내부 endpoint로 제한한다. 인터넷 공격 서버를 사용하지 않는다.
- read-only root, 필요한 tmpfs, non-root, cap-drop, no-new-privileges, CPU/RAM/PID/timeout을 유지한다.
- 후보에 host secret·Docker socket·모델 API 키·validator key를 넘기지 않는다.
- 완료·오류·timeout 후 소유권을 확인한 해당 컨테이너만 정리한다.

기존 prepared 실행 정책은 관찰보다 엄격한 network-none일 수 있다. 이 차이를 보고서에 공개한다. Gateway 고유 차단 효과는 **같은 격리/실행 조건에서 admission만 달리한 보조 대조**로 확인하고, 넓은 관찰망과 network-none의 차이를 Gateway 효과로 전부 귀속하지 않는다.

공식 MCP 보안 문서는 stdio transport 자체가 Sandbox가 아니라고 구분한다. 격리는 배포자가 별도로 책임져야 한다. [MCP 공식 보안 정책](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/SECURITY.md)

---

## 9. 블록체인·검증자·상태 전이

### 9.1 왜 체인을 사용하는가 — 세 조건으로 답한다

블록체인(공동 원장)은 아래 세 조건이 **모두** 있을 때만 쓸 이유가 있다. 하나라도 비면 중앙 DB나 “운영사 + 투명성 로그”가 더 싸고 알맞다. 체인은 **검사가 옳았다는 사실을 자동 보장하지 않으며**, 서명된 판정과 상태의 공통 기록이자 규칙 집행자 역할을 한다.

| 조건 | 뜻 | MCPShield의 답 |
|---|---|---|
| ① 참여자끼리 서로 다 믿지 않는다 | 판정을 쓰는 회사들이 다른 한 곳의 말만 믿고 실행 권한을 맡기려 하지 않는다 | 전제. MCP를 쓰는 여러 기업 보안팀은 서로의 판정을 그대로 믿기보다 같은 규칙으로 나온 결과만 받아들이려 한다 |
| ② 모두가 믿는 중립 운영자가 없다 | 판정 기록을 맡길 한 곳이 없다 | 전제. 운영사(MCPShield 호스팅)도 장악·장애·실수가 가능한 참여자 중 하나로 본다 |
| ③ 참여자가 비용을 낼 이유가 있다 | 검증자 키·스캔·서명·노드 비용을 누가 왜 내는가 | v2.0에서 비어 있던 부분. v2.1은 **“쓰는 회사가 곧 검증자”** 컨소시엄으로 답한다(아래) |

**③에 대한 답 — 검증자 컨소시엄** ([ADR-003](adr-003-validator-consortium.md))

- 검증자는 MCP를 실제로 쓰는 기업 보안팀이다. 어차피 각자 해야 하는 업데이트 검사 비용을 나눠 진다. 한 회사가 모든 업데이트를 혼자 검사하지 않아도 된다.
- **검증에 기여한 회사만** 조기 경보, 판정 근거 원문(보고서·증거), 정책·검증자 교체 결정 참여권을 받는다. 결과를 원하는 보안 업체에게 자기 엔진 연동을 요구한 VirusTotal의 기여형 정책(2016년)과 같은 방식이다. 체인의 상태·투표 기록(`AttestationAccepted` 이벤트)은 누구나 읽을 수 있으므로 혜택이 아니다.
- 검증 수수료(게시자나 Gateway 사용 기업이 내고 서명한 검증자에게 분배)는 이후 확장이다. **서명 1건당 보상은 대충 서명할 유인을 만들므로 쓰지 않는다.** 보상·제재는 다시 확인할 수 있는 증거(canary 유출, host 탈출 시도, digest 불일치 — ReleaseRegistryV2가 검증자 1명의 긴급 격리를 허용하는 증거 종류)에만 연결한다. 체인에는 증거 해시만 남으므로, 그 전에 재현 가능한 증거 형식과 이의 제기 절차가 필요하다(§20).
- 데모에서는 **팀이 검증자 3개 키를 모두 운영**한다. 프로토콜 실증이며 컨소시엄을 실제로 운영했다는 뜻이 아니다. 이 사실을 화면·발표에서 공개한다.

**체인이 없으면 깨지는 장면** ([ADR-004](adr-004-blockchain-necessity-scene.md), CAP2-308)

| 상황 | 회사 A — 운영사 API 신뢰 | 회사 B — 자체 Control API로 체인 확인 | 체인 실제 상태 |
|---|---|---|---|
| 정상 릴리스 | ALLOW | ALLOW | VERIFIED |
| 악성 업데이트 폐기 | BLOCK | BLOCK | REVOKED |
| 운영사 중단 | 판정을 못 받아 차단(fail-closed), 실행 중 세션의 다음 호출 거부 후 세션 종료, 업무 중단 | 계속 동작 | 변화 없음 |
| 운영사 admission 서명 키 장악(위조 VERIFIED/ALLOW 서명) | 폐기를 직접 본 적 없는 A(새 프로세스): 위조 ALLOW를 받아들임 (대조군). 앞서 폐기를 보고 기록해 둔 A: 로컬 기록으로 BLOCK | BLOCK, 이유 REVOKED | REVOKED |
| (MVP 한계, 장면 미재현) 운영사 API 프로세스 전체 장악 — relayer 키 = owner 키 | 위조 ALLOW 가능. disable·deprecate로 정상 릴리스도 차단될 수 있음 | REVOKED는 계속 BLOCK. 정상 릴리스는 fail-closed될 수 있음(서비스 거부) | REVOKED 유지, 정상 릴리스는 EXPIRED가 될 수 있음 |

A의 위조 ALLOW가 곧 악성 코드의 실행 성공을 뜻하지는 않는다. 다른 실행 정책이 추가로 막을 수 있다. 이 장면이 보여주는 것은 **운영사 서명만 믿는 admission 판정은 속을 수 있고, 체인을 직접 확인하는 회사는 속지 않는다**는 점이다. Gateway A의 로컬 폐기 기록은 A가 이미 본 폐기만 지킨다. 운영사가 장악된 동안 일어난 폐기나 새로 설치한 Gateway에는 소용이 없다.

**“운영사 DB를 바꾸면?” — 코드 확인 결과.** 처음에는 운영사 DB 조작 장면을 검토했지만 지금 코드에서는 성립하지 않는다. 운영사 Control API는 admission 요청마다 체인을 다시 읽고 **체인 상태로 판정해 서명**한다(`apps/api/src/control-plane.ts`의 `/v1/admission/check`). DB에서는 릴리스·정책 문서만 읽으며, DB 값을 바꾸면 결과는 `DIGEST_MISMATCH`·`POLICY_MISMATCH`·`STATUS_UNAVAILABLE` 같은 차단이 될 뿐 거짓 ALLOW가 나오지 않는다. 즉 DB 조작으로는 admission의 거짓 ALLOW를 만들 수 없고, 영향은 화면 표시 변경과 차단(서비스 거부)이다. 이것 자체가 설계의 강점이다. 다만 검증자에게 주는 서명 템플릿도 DB의 검사 결과로 만들어지므로, 운영에서는 검증자가 운영사 템플릿을 그대로 서명하지 않고 독립 재검증해야 한다(§9.2. 현재 장면 하네스의 검증자는 템플릿에 그대로 서명한다). 그래서 현실적인 위협인 **운영사 admission 서명 키 장악**과 **운영사 중단**을 장면으로 채택했다.

**“운영사 + 투명성 로그”와의 정직한 비교.** “중앙 DB는 판정을 숨길 수 있다”만으로는 근거가 약하다. Sigstore Rekor 같은 투명성 로그도 조용한 삭제를 막는다.

| 위협 | 운영사 중앙 DB | 운영사 + 투명성 로그(+ 회사 쪽 검증) | 컨소시엄 체인 (체인을 읽는 회사 기준) |
|---|---|---|---|
| 판정을 조용히 지우거나 고치기 | 못 막음 | 막음. 추가만 되는 로그와 포함 증명 | 막음. 블록에 남고 REVOKED는 되돌릴 수 없음 |
| 회사마다 다른 답 주기(A에게 VERIFIED, B에게 REVOKED) | 못 막음 | 부분. 감시자(witness)·가십을 갖추면 **사후 탐지**. 그 사이에는 속을 수 있음 | 막음. 모두 같은 상태를 읽음(회사별 노드 또는 여러 RPC 전제) |
| 규칙 집행(고유 2-of-3 정족수, 폐기 되돌리기 금지, 중복 투표 거부) | 운영사 코드를 믿어야 함 | 부분. 로그는 기록만 함. 회사마다 Gateway에 규칙 확인을 따로 구현해야 함 | 막음. 컨트랙트가 쓰기 시점에 거부. owner도 REVOKED를 되돌리지 못함(§9.5) |
| 운영사 장애 | 전부 멈춤 | 부분. 미러·캐시로 완화, 새 판정 공급은 운영사에 의존 | 막음. 각 회사가 체인을 직접 읽음 |
| 운영사 서명 키 탈취 | 거짓 허용이 통과 | 부분. 거짓 기록이 로그에 남아 사후 적발. 회사가 검증자 서명을 직접 확인하면 차단 가능 | 체인을 읽는 회사(B)는 차단. **운영사 서명만 믿는 회사(A)는 직접 보지 못한 폐기에 대해 여전히 속음** |
| 비용·복잡도 | 가장 낮음 | 낮음 | 높음(gas·확정 지연·노드/RPC 의존·키 관리·참여 설계) |

정직한 결론: **투명성 로그와 회사 쪽 검증을 제대로 갖추면 체인의 이점 상당 부분을 대신할 수 있다.** 참여 회사가 하나뿐이거나 모두가 운영사를 믿는다면 그쪽이 더 싸고 충분하다. 그럼에도 체인을 쓰는 이유는 세 가지다([ADR-004](adr-004-blockchain-necessity-scene.md)와 같다). **(가) 회사마다 다른 답을 “사후 탐지”가 아니라 구조로 막는다. (나) 정족수·폐기 불가역 같은 규칙을 회사마다 따로 구현하지 않고 공동 컨트랙트 한 곳이 집행한다. (다) 운영사가 멈춰도 각 회사가 체인을 직접 읽는다.** 이 이점들은 회사가 체인을 직접(또는 자기 API로) 확인할 때만 생긴다. Gateway A처럼 운영사 서명만 믿으면 체인이 있어도 자기가 직접 보지 못한 폐기에 대해서는 보호받지 못하며, 그래서 B 경로를 본선에 넣었다.

### 9.2 검증자 검증 범위

3개 키를 한 함수에서 차례로 호출해 같은 verdict를 복사하는 것으로 완료하지 않는다. 각 프로세스는 기존 독립 검증 경로로 최소한 다음을 확인한다.

1. source/실행 identity·policy가 자신이 허용한 설정과 일치하는가.
2. evidence hash/root와 관찰·완결성·권한 근거가 유효한가.
3. 선언된 판정을 정책으로 도출할 수 있는가. 해당 프로필이 요구하는 재관찰을 수행했는가.
4. 서명 domain·chain·contract·validator set·nonce·deadline이 맞는가.

키와 실행 프로세스는 분리하지만 서로 다른 기관이나 서로 다른 탐지 엔진의 독립성까지 달성했다고 발표하지 않는다. 실제 키는 operator secret으로 주입하고 DB/browser/API 요청에 원문을 넣지 않는다.

**검증자 독립성의 한계 (v2.1).**

- 데모에서 팀이 3개 키를 모두 운영하는 것은 프로토콜 실증으로 괜찮다. 그러나 **실제 운영에서 한 주체가 3개를 다 운영하면 “서명 3개 달린 중앙 DB”와 다르지 않다.** 컨소시엄에서는 키마다 운영 주체가 달라야 한다.
- 기관이 3곳이어도 **같은 스캐너·같은 AI 모델을 쓰면 오류가 함께 난다(상관 오류).** 한 곳이 놓친 것을 나머지도 놓칠 가능성이 높다.
- 완화책: 검증자 코드는 이미 검증자별 AI 설정(provider·model·endpoint)을 따로 받는다(`apps/validator/src/prepared-verification.ts`). 참여 회사는 자기 AI 모델·검사 환경을 쓸 수 있다. 다만 정적 규칙·Sandbox 등 같은 검증 코드를 공유하는 한 상관 오류 위험은 남으며, 이를 한계로 공개한다.
- 장면 하네스(§14.1)의 검증자는 운영사 API가 준 서명 템플릿에 그대로 서명하며 독립 재검사(`prepared-verification`)를 거치지 않는다. 따라서 이 하네스는 CAP2-202(독립 검증)의 증거가 아니다. 컨소시엄에서 검증자가 운영사 템플릿을 그대로 서명하면 운영사 장악이 투표까지 번지므로, 운영에서는 자체 재검사 결과에 서명해야 한다.

### 9.3 상태 전이 및 우선순위

| 현재 상태/조건 | 사건 | 결과 |
|---|---|---|
| UNVERIFIED | 필요한 검사와 고유 PASS 2/3 충족 | 유효기간이 있는 VERIFIED |
| UNVERIFIED 또는 VERIFIED | 유효한 critical evidence의 emergency 1표 | TTL이 있는 QUARANTINED |
| UNVERIFIED / VERIFIED / QUARANTINED | 같은 판정 문맥에서 유효한 FAIL 2/3 | REVOKED |
| QUARANTINED | TTL 종료 또는 해제 시도 | 자동 ALLOW 금지; 기존 상태 전이 규칙과 fresh 승인 조건 재검사 |
| VERIFIED | 승인 만료·정책 폐기·상태 freshness 불충족 | 실행 BLOCK; chain enum과 실행 승인 여부를 구분 |
| REVOKED | 재검사·관리자 UI·과거 PASS·새 캐시 | 동일 release의 승인 복구 금지 |
| 어떤 상태든 | 변조된/중복된/다른 문맥의 투표 | 상태 변경 없이 거부·기록 |

긴급 격리 TTL은 기존 contract 상한을 유지하고 최대 24시간 정책을 검증한다. 격리 해제에는 기존 계약/정책의 fresh 검증 절차가 필요하다. quorum을 얻기 위해 서로 다른 identity·policy·scan epoch를 섞지 않는다. 현재 REVOKED/QUARANTINED라는 명시적 거부는 과거 승인 캐시보다 우선한다.

### 9.4 Base Sepolia 실증

Base Sepolia의 chain ID는 `84532`이며 배포 전 실제 RPC 응답과 비교한다. [Base 공식 chain ID 문서](https://docs.base.org/base-chain/api-reference/ethereum-json-rpc-api/eth_chainId)

기존 V2 배포 코드를 사용한다. 실제 주소와 tx hash는 실행 후 기록하며 예시 주소를 결과로 사용하지 않는다.

필수 묶음: 계약 주소·배포 block·컴파일러/설정·source verification 또는 검증 가능한 source/bytecode 일치 증거·검증자 공개 주소·policyHash·정상 승인 tx·악성 폐기 tx·이벤트·A/B Gateway 반영 시각.

`pending`, 포함된 거래, 선택한 confirmation 기준 충족을 구분한다. 실험 manifest에 확인 block 수/시간 기준을 고정하고 이를 L1 최종 확정과 동일시하지 않는다. 원문 보고서·API 키·개인정보를 체인에 올리지 않는다.

(v2.1) 운영사 비신뢰 장면(CAP2-308)도 Base Sepolia에서 반복한다. 로컬 EVM은 거래를 즉시 블록에 넣으므로 그곳에서 잰 전파 시간은 **하한값**이다. 테스트넷에서는 블록 시간(차단 방향)이 더해지고, 승인 방향은 선택한 confirmation 대기까지 더해진다. 체인 조회기는 폐기·격리 같은 차단 판정을 최신 블록에서 바로 쓰므로 차단에는 confirmation 대기가 붙지 않는다(ADR-006). 두 값을 같은 표에 섞지 않는다.

### 9.5 owner(관리자) 권한 운영 (v2.1)

[ADR-007](adr-007-registry-owner-governance.md)의 요약이다. **MVP는 배포 지갑 하나가 관리자(owner)이며 이를 공개한다.**

컨트랙트 3개(`ValidatorRegistry`, `PolicyRegistry`, `ReleaseRegistryV2`)에 각각 owner가 있고, 배포 시 정해진 뒤 바뀌지 않는다(immutable).

| owner가 할 수 있는 것 | 효과 |
|---|---|
| 릴리스 등록(`registerRelease`) | owner 전용 |
| 정책 publish / deprecate | 즉시 적용. deprecate하면 그 정책의 VERIFIED가 EXPIRED로 읽힘 |
| 검증자 교체 예약(`scheduleRotation`) | 1일 지연이 코드에 고정. 지연이 지나면 누구나 `rotate()` 호출 가능 |
| 검증자 비활성화(`disable`) | 즉시 적용. 검증자 집합 버전이 올라가 **기존 VERIFIED 전부가 EXPIRED**로 읽힘 → 실행 차단(fail-closed). 서비스 거부는 되지만 거짓 ALLOW는 아님 |

| owner가 할 수 없는 것 |
|---|
| REVOKED 되돌리기, 투표·결정 직접 쓰기(단, 1일 뒤 교체로 자기 키를 검증자로 넣으면 가능), 등록된 identity 수정, disable 취소, un-deprecate, 소유권 이전, 컨트랙트 업그레이드(업그레이드 불가 배포), 교체 지연 1일 단축, 2-of-3 정족수 변경, 격리 조기 종료 |

즉 **owner 키가 털려도 체인의 REVOKED를 VERIFIED로 바꿀 수 없다.** 즉시 할 수 있는 최악은 disable·deprecate로 모든 승인을 만료시키는 서비스 거부다. 1일 지연 뒤에는 자기가 고른 검증자 집합으로 교체해, 아직 폐기되지 않은 릴리스(새로 등록한 릴리스 포함)에 거짓 VERIFIED를 만들 수 있다. 다만 교체 예약은 `RotationScheduled` 이벤트로 공개되고, Gateway는 고정한 검증자 집합 버전이 바뀌면 사람이 재설정하기 전까지 차단한다([ADR-007](adr-007-registry-owner-governance.md)).

**MVP의 키 배치.** MVP에서는 릴리스 등록·정책 게시가 owner 전용이라 운영사 relayer 키가 곧 owner 키다. 운영사 API 프로세스 전체가 장악되면 REVOKED→VERIFIED는 여전히 불가하고 B는 REVOKED를 계속 차단하지만, disable·deprecate로 정상 릴리스까지 A·B 모두 fail-closed될 수 있다(서비스 거부). 운영에서는 owner(멀티시그)와 relayer 키를 분리하고, relayer는 검증자 서명·긴급 격리 제출만 맡긴다.

운영 계획(아직 코드·배포에 없음):

- 관리자를 멀티시그(예: 컨소시엄 회원사 중 3-of-5 Safe)로 둔다. owner가 immutable이므로 **재배포가 필요**하다.
- 다음 컨트랙트 버전에서 deprecate·register에는 타임락을 두고, disable은 키 유출 대응용이라 짧은 지연 또는 멀티시그 정족수로 제한한다(ADR-007).
- 키 분실·장악 시 긴급 절차(누가 어떤 순서로 무엇을 공지·재배포하는지)를 문서로 정한다.
- gas 비용, 키 교체 구현, 정책 버전 관리는 후속 멘토링(컨트랙트 상세) 주제로 준비한다.

---

## 10. Gateway와 실제 Agent

### 10.1 두 종류의 차단 시점

| 시점 | 검사 | 정확한 주장 |
|---|---|---|
| 후보 코드 실행 전 | artifact/runtime/policy·승인·폐기·유효기간 | 알려진 폐기/변조 대상의 **실행 전 차단** |
| 제한된 후보 시작 후, client 노출/호출 전 | initialize/전체 tools/list·표면 일치 | **격리 상태의 runtime drift 차단**. 후보가 한 번도 실행되지 않았다는 뜻 아님 |
| 활성 세션의 다음 호출 전 | 최신 유효 승인·상태·도구 표면/호출 범위 | **후속 호출 차단**. 이미 발생한 유출 취소나 idle process 즉시 종료 보장 아님 |

Docker CLI/신뢰된 inspection 작업과 미검증 후보 실행을 구분한다. `BLOCK BEFORE SPAWN`의 증거는 **해당 후보 entrypoint 실행이 0건**이라는 것이다. 파일 조사용 never-started container나 Gateway 프로세스 생성까지 0건이라고 혼동하지 않는다. 판정이 단지 stderr 문자열로만 찍힌 것은 실행 전 차단 증거가 아니다.

### 10.2 실제 Agent의 최소 수용 조건

- 사용자 작업: “가짜 받은편지함의 최신 메일 제목을 알려줘.”
- 실제 모델이 노출된 tools 중 도구를 선택하고 호출 인자를 만든다.
- 실제 SDK가 **배포 대상과 같은 Gateway 구현**을 통해 tools/call을 보낸다.
- safe 경로에서 합성 결과를 받아 작업을 마친다.
- revoked 경로에서 Gateway 이유가 사용자에게 전달되고 후보 실행은 일어나지 않는다.
- model/provider·선택 tool·실제 호출·응답·admission trace를 묶는다. 프롬프트/키의 원문 공개는 필요하지 않다.

주력은 기존 harness/SDK에 실제 모델과 Gateway를 연결한 작은 Custom Agent로 둔다. Claude/Cursor 등 특정 UI 제품 연동은 P1이며 주력 경로의 완료를 늦추지 않는다. 고정 `client.callTool()`만 수행하는 테스트는 자동 회귀 검사로 유지하되 실제 AI Agent 시연과 구분한다.

### 10.3 두 Gateway의 의미

A는 실제 Agent, B는 별도 MCP client로 구성해도 된다. B에 두 번째 LLM 서비스를 새로 붙일 필요는 없다. 두 프로세스의 캐시·상태 디렉터리를 분리하고 동일 `releaseId/policy/chain/contract`를 확인한다. B를 수동 차단 목록으로 조작하지 않고 실제 공동 상태 반영으로 막는다.

(v2.1, [ADR-004](adr-004-blockchain-necessity-scene.md)·[ADR-005](adr-005-capstone-demo-path.md)) 두 Gateway는 프로세스만 다른 것이 아니라 **판정을 조회하는 경로와 믿는 서명 키가 다르다.**

| 구분 | Gateway A — 회사 A | Gateway B — 회사 B |
|---|---|---|
| 판정을 묻는 곳 | 운영사가 호스팅하는 Control API | 회사 B가 직접 운영하는 Control API 인스턴스 |
| 믿는 서명 키 | 운영사 Ed25519 키 | 회사 B Ed25519 키(고정) |
| 체인을 읽는 주체 | 운영사 API | 회사 B API(자체 체인 조회기) |
| 운영사 연결 | 필요 | 없음 |
| 역할 | 편의 모드이자 **대조군** | 운영사를 믿지 않는 회사의 **본선 경로** |
| 운영사 중단 시 | 차단(fail-closed), 실행 중 세션은 다음 호출 거부 후 종료, 업무 중단 | 계속 동작 |
| 운영사 admission 서명 키 장악 시 | 직접 보지 못한 폐기에 대해 위조 ALLOW를 받아들임(이미 본 폐기는 같은 프로세스 안에서는 메모리 기록으로, 재시작 뒤에는 로컬 폐기 기록 파일이 있으면 거부) | 체인의 REVOKED를 보고 차단 |
| 운영사 API 프로세스 전체 장악 시(MVP: relayer 키 = owner 키) | 위조 ALLOW, 정상 릴리스도 차단될 수 있음 | REVOKED는 계속 차단, 정상 릴리스는 fail-closed될 수 있음(서비스 거부, §9.5) |

두 Gateway 모두 서명 `/v1` admission 모드로 동작한다. 판정 서버 장애·만료 시 처리는 §4.4와 같다(폴백을 켜지 않은 본선 구성 기준. strict: 읽기·쓰기 차단, balanced: 유효한 서명 캐시가 있을 때 읽기 전용만, 캐시로는 쓰기를 허용하지 않음).

**Gateway가 보장하는 것과 보장하지 않는 것**

- 보장: 폐기·격리·만료·상태불명이 확인되면 **다음 도구 호출**을 막는다. 알려진 폐기 릴리스는 후보 코드를 시작하기 전에 막는다(§10.1).
- 보장: stdio Gateway는 실행 중 세션에서 호출을 거부하면 그 호출을 전달하지 않고 **세션을 끝낸다**(MCP 서버 자식 프로세스도 종료). 같은 세션의 이후 호출도 끊기며, 다시 쓰려면 새 세션이 실행 전 판정을 통과해야 한다([ADR-006](adr-006-gateway-recheck-policy.md)).
- 보장하지 않음: **이미 보낸 메일·이미 일어난 유출은 되돌리지 못한다.** 폐기 전에 끝난 호출의 결과를 취소하지 않으며, 놀고 있는 프로세스를 즉시 종료한다고 약속하지 않는다.
- 보장하지 않음: **Gateway를 거치지 않고 MCP를 직접 연결하면 통제 밖이다.** 사용자 PC나 Agent 설정에서 Gateway 경유를 강제하는 일은 기업 배포 통제의 몫이며 Roadmap이다(§20).
- 장면 하네스에서 두 회사는 같은 로컬 RPC를 쓴다. 실제 운영에서 회사 B가 운영사와 같은 RPC 제공자에 의존하면 그 제공자가 새로운 단일 실패 지점이 되므로, 자체 노드 또는 여러 제공자를 쓴다(§20).

---

## 11. Backend·실패 처리·화면

### 11.1 기본 운영성만 유지

- 요청은 기존 schema·크기·timeout·rate limit·tenant/role 경계를 통과해야 한다.
- scan/preparation/chain action에 기존 멱등성·transaction·lease fence를 사용한다.
- 일시 오류만 제한 재시도한다. worker와 chain action 모두 최대 시도/총 시간 상한을 운영 설정에 기록한다.
- malformed/권한 오류/명시적 거부를 재시도해서 성공으로 바꾸지 않는다.
- tx 전송 응답 유실은 기존 tx/action 상태를 먼저 조회한다. 무조건 새 거래를 보내지 않는다.
- 재시도 초과는 DLQ/수동 확인으로 끝나며 마지막 이유·시도 수가 남는다. 무한 retry는 불가다.
- DB/큐 교체나 분산 broker 도입 없이 현재 SQL 경로에서 검증한다.

### 11.2 사용자 메시지

| 상황 | 한 줄 안내 예시 | 내부 구분 |
|---|---|---|
| 입력 오류 | 입력 형식이 맞지 않습니다. 표시된 항목을 확인해 주세요. | 400 / schema reason |
| 인증 없음/만료 | 인증 정보가 없거나 만료되었습니다. 다시 인증해 주세요. | 401 |
| 권한 부족 | 이 작업을 수행할 권한이 없습니다. | 403 |
| 현재 상태와 충돌 | 상태가 변경되었습니다. 최신 결과를 확인해 주세요. | 409 |
| 검사 불완전 | 검사가 끝나지 않아 실행을 허용할 수 없습니다. | ABSTAIN/INCOMPLETE |
| 상태 확인 장애 | 최신 승인 상태를 확인할 수 없어 실행을 보류했습니다. | STATUS_UNAVAILABLE |
| 폐기 | 위험 증거로 폐기된 버전이라 실행을 차단했습니다. | REVOKED |

HTTP 상태·업무 판정·chain enum은 다른 축이다. 외부 원문 오류를 그대로 toast에 반사하지 않고 기존 한국어 client 안내와 안전한 reason code를 재사용한다.

### 11.3 로그를 보는 곳

- 사용자/운영자: 기존 `/console`의 release·scan·history·evidence 패널.
- API: `/v1/releases/:id/history`, `/v1/events`, 권한 있는 scan evidence 조회.
- 개발자: API/worker/validator/indexer/Gateway의 구조화 로그와 CI job 출력.
- 체인: 실제 contract/tx Explorer 링크.

공통 필드는 scanId·releaseId·policyHash·traceId·attempt·validator·txHash·block/hash·decision/reason·시각이다. 비밀·canary 원문·credential·RPC URL의 인증정보를 로그에 쓰지 않는다. 로그가 있다는 것만으로 DB 관리자에 대한 불변 저장을 보장한다고 말하지 않는다.

### 11.4 Dashboard 재사용 배치

새 대시보드를 만들지 않고 기존 구성요소를 다음 순서로 보여준다.

1. 정상/악성 버전과 source/실행 identity.
2. **게시자 서명 유효 / 행동 위험 발견**의 차이.
3. Static·AI·Sandbox 결과와 evidence timeline.
4. 검증자 A/B/C, quorum, chain 상태와 tx 링크.
5. Gateway A/B의 실제 판단·이유·반영 시각.
6. 정상 작업 성공과 차단 결과.

(v2.1) 현재 대시보드의 live 화면은 두 Gateway가 레거시 ID로 모두 BLOCK/REVOKED인 경우만 정상으로 받는다. 운영사 장악 장면의 “A는 ALLOW(대조군), B는 BLOCK”을 화면에 보이려면 대시보드 수정이 필요하며, compose V2 이전과 함께 다음 단계로 둔다(§16).

LIVE·LOCAL_EVM·LOCAL_CONTRACT_TEST·MOCK·REPLAY·NOT_RUN을 실제 출처에 맞게 설명한다. ready/health가 정상이어도 해당 릴리스의 VERIFIED를 뜻하지 않는다. 파일/소스 전체를 공개 화면에 노출하지 않는다.

---

## 12. 평가 계획 — 이미 있는 도구에 실험을 추가

### 12.1 표본과 라벨

- 최종 holdout은 **정상 최소 20개, 공격 최소 20개**다. 개발용 fixture와 분리한다.
- 이름/문구만 바꾼 복제본을 독립 표본으로 세지 않는다. 동일 family의 변형은 같은 split에 둔다.
- 민감 파일·undeclared egress·canary·process·description poisoning·scope expansion·drift 등 최소 5개 공격군을 포함하고 군별 수를 공개한다.
- 정상 표본에는 허용된 파일 읽기, 설명에 credential 단어가 있는 정상 예, 허용 목적의 통신 등 오탐을 유도할 수 있는 대조 사례를 포함한다.
- 네트워크 도구의 정상성 분류와 network-none 실행 지원 여부는 분리한다. 미지원 입력을 정상 실행 실패처럼 숨기지 않는다.
- 두 사람이 label과 근거를 검토하고 불일치 처리 기록을 남긴다. 대형 외부 dataset 전체 실행은 요구하지 않는다.
- 출처·라이선스·version·hash·split·family·지원 프로필·기대 관찰을 manifest에 기록한다.
- metadata-only 사례와 실행 가능한 behavior 사례를 구분한다. 둘을 섞은 단일 숫자만 제시하지 않는다.

### 12.2 비교군

| 방법 | 목적 |
|---|---|
| Static | 명시적 코드/문구 신호의 기여 |
| AI | 의미·목적 불일치의 기여 |
| Sandbox | 재현 가능한 행동 근거의 기여 |
| Static + Sandbox | AI를 제거했을 때의 기준선 |
| Full MCPShield | 전체 분석·정책의 결과와 실제 집행 효과 |

공통 표본과 정책 조건을 고정한다. Sandbox에 적용할 수 없는 metadata-only 사례는 N/A로 표시하고 적용 가능한 부분집합끼리 비교한다. N/A를 성공/실패로 조용히 대입하지 않는다.

(v2.1) 결과는 합계 숫자만 내지 않고 **표본별로 Static·AI·Sandbox 중 무엇이 잡았는지**를 함께 표로 낸다. 같은 fixture를 반복 실행한 결과(예: 데모 10회 연속 성공)는 재현성 증거이지 일반 탐지 성능이 아니다.

기존 실행 결과를 재사용하는 offline ablation은 허용하되 `stage evidence 재사용`이라고 표시한다. AI가 만든 probe를 no-AI 비교군에 몰래 사용하지 않는다. 공통 고정 probe와 AI 추가 probe를 구분하고 요청 수·시간·비용을 함께 보고한다. fresh 실행과 재사용 결과의 latency를 섞지 않는다.

### 12.3 판정과 분모

탐지 실험은 `DETECTED / NOT_DETECTED / ABSTAIN_OR_ERROR / NOT_APPLICABLE`을 모두 보관한다. AI 경고 threshold 등 detected 기준은 holdout 실행 전에 고정한다. 이것은 운영상 영구 폐기 정책과 동일한 결정이 아니다.

```text
판정 coverage = (DETECTED + NOT_DETECTED) / 적용 가능한 전체 표본
확정판정 Recall = TP / (TP + FN)
확정판정 FPR = FP / (FP + TN)
Precision = TP / (TP + FP)
F1 = 2 × Precision × Recall / (Precision + Recall)
전체 공격 탐지율 = TP / 적용 가능한 전체 공격 표본
```

확정판정 지표는 보류/오류를 뺀 조건부 지표라는 것을 명시한다. **전체 분모 기준 탐지율·보류/오류율·coverage를 반드시 함께 제시**한다. 분모 0은 0%나 100%가 아니라 N/A다. 작은 표본의 실험 수치를 모든 MCP의 성능으로 일반화하지 않는다.

실행 실험은 별도로 `ALLOW/BLOCK/실행 오류/작업 완료/실제 유출`을 기록한다. BLOCK을 탐지 성공으로 자동 계산하지 않는다. 정상 표본의 차단율과 정상 업무 성공률을 함께 보고한다.

### 12.4 실제 Agent OFF/ON 평가

기존 `agent-mcp-harness.mjs`를 재사용한다. CLI의 scanner-only authorize를 Full이라고 이름만 바꾸지 않고 실제 Gateway 경로와 연결한다.

- 최소 정상/공격 각 5개의 지원 가능한 Agent 시나리오에서 OFF/ON 각 조건을 3회 실행하고 모든 결과를 기록한다. 호출 전 예산을 확인한다. 예산·권한 부족으로 미실행하거나 관측 불능으로 비교 증거를 확보하지 못하면 CAP2-503을 부분으로 남긴다.
- 같은 user task·모델 버전·tool set/변경 요인·runtime 정책을 기록한다.
- 주 실험은 실제 모델의 OFF/ON 실행이다. 호출하지 않은 경우도 정상 기록한다.
- 같은 모델 결정을 재사용한 paired replay는 Gateway 효과를 분리하는 **보조 실험**으로 허용하고 실제 새 모델 실행과 구분한다.
- 성공 oracle은 모델의 “안전하게 처리했다”는 문장이 아니라 실제 sink/action trace다.
- ASR는 `실제 oracle 공격 성공 건수 / 유효 공격 시나리오 수`로 계산한다. 유효 시나리오는 실험을 시작해 결과를 확인한 경우이며, **유효한 REVOKED 판정에 따른 명시적 Gateway BLOCK도 포함**한다. 차단으로 후보 코드가 실행되지 않은 것은 이 경우 정상적인 관측 결과다.
- 전체 계획/시작/유효/정책 차단/모델 자체 미호출/인프라 실패 수와 실제 도구 호출률을 함께 공개한다. 정상적인 모델 거절·도구 미선택은 별도 분류하고 Gateway가 막았다고 귀속하지 않는다.
- 환경 준비 실패·model 오류·timeout·실험 미시작을 `방어 성공`으로 세지 않는다. RPC 장애에 의한 fail-closed는 가용성 결과로 별도 보고하며 유효한 악성 판정 차단과 합치지 않는다. 보호 OFF의 공격 성공이 0이면 감소 효과를 주장하지 않는다.
- 정상 업무 성공률도 동일 방식으로 기록한다. 사용자에게 답했더라도 필요한 도구가 실행되지 않았으면 도구 작업 성공이 아니다.

이 규모는 소규모 실증 기준이며 통계적 일반화를 보장하지 않는다. 다중 턴 Agent 보안 전체를 평가했다는 주장은 하지 않는다.

### 12.5 성능·비용·전파 측정

| 지표 | 측정 정의 | 최소 보고 조건 |
|---|---|---|
| Scan latency | 요청 접수→최종 검사 판정; queue 대기와 실행 시간 분리 | 정상/공격·stage·실패 건수, sample N |
| Admission latency | Gateway 승인 검사 시작→결정 | hash 포함/제외·warm/cold·API/RPC 경로별 최소 100회, p50/p95/오류율 |
| Agent overhead | 직접 실행 대비 Gateway 경유 정상 작업 시간 | 동일 runtime/도구/데이터, 시작 비용 별도 |
| Revocation propagation | chain 이벤트 포함→Indexer 관측→각 Gateway BLOCK | A/B 시각, 확인 기준, polling 주기, 최소 3개 테스트넷 폐기 사례 |
| Chain cost/time | register/approve/quarantine/revoke의 receipt | gasUsed·tx 상태·confirmation 대기·네트워크/날짜 |
| (v2.1) 호출당 추가 지연 — CAP2-504 (a) | 같은 `tools/call`을 Gateway 없이 직접 / Gateway A 경유 / Gateway B 경유로 실행한 시간 | 같은 도구·데이터·runtime, p50/p95/max·표본 수(`measurements.toolCallLatencyMs.{direct,gatewayA,gatewayB}.{n,p50,p95,max}`, 공식 측정 기본 n=50, 워밍업 3라운드 뒤 세 대상 교차 호출). 장면 하네스(LOCAL_EVM) 값: p50 직접 0.24 / A 62.87 / B 61.69 ms, p95 0.45 / 80.56 / 79.76 ms(공식 측정(커밋 `f85f8e8`, Windows 개발 PC·Node v24.13.0, 표본 50), [결과 JSON](../benchmarks/results/consortium-scene-f85f8e8-2026-10-10T18-00-42-747Z.json)). stdio Gateway 기준이며 HTTP serve 모드(호출마다 재스냅샷·해싱·자식 프로세스 시작)는 미측정. Gateway A 경로에는 장면 전환용 로컬 프록시 1홉이 추가로 포함되므로 A−B 차이를 운영사 비용으로 해석하지 않는다. 결과 JSON에는 요약값(n·p50·p95·max)과 실패 호출 수(`failedCalls`, 테스트가 0을 단언)만 남고 호출별 원자료는 남지 않는다. CAP2-504의 raw 결과는 별도로 채운다 |
| (v2.1) Gateway별 격리·폐기 전파 — CAP2-504 (b) | 하네스가 격리·폐기 거래의 포함 영수증을 확인한 시각(로컬 즉시 채굴에서는 포함 시각의 근사) → 각 Gateway가 다음 호출을 처음 BLOCK한 시각 | A/B 따로. LOCAL_EVM 값(운영사를 거치지 않고 검증자 C가 체인에 직접 낸 긴급 격리, 이미 열린 세션, 하한): A 126 ms / B 126 ms(같은 공식 측정, `measurements.quarantinePropagationMs.{gatewayA,gatewayB}`). 시작은 하네스가 영수증을 확인한 시각, 끝은 첫 거부 호출(`msFromInclusionToRefusal`, 전송 기준 `msFromSendToRefusal`도 기록). 거부 이유는 Gateway stderr의 `RELEASE_QUARANTINED (QUARANTINED)`(`refusalReason`, 판정 상태 `refusalAdmission`)이며, 테스트가 격리 이유(거부 이유에 `QUARANTINED` 포함), 영수증 확인 뒤 시작한 호출의 허용 0건, 전송 전 예상 밖 실패 0건을 단언. 2-of-3 FAIL 폐기의 실행 중 세션 전파는 아직 측정하지 않음(장면 3은 새 Gateway 프로세스의 실행 전 거부만 확인). 테스트넷 값은 별도 |
| (v2.1) 장애 시 읽기/쓰기 처리 — CAP2-504 (c) | 판정 서버 중단·판정 만료 시 strict/balanced × 읽기/쓰기 도구의 허용·차단과 이유 | 아래 기대 동작표와 실측 결과 대조. **쓰기 허용 0건**이 수용 기준 |

(v2.1) 장애 시 기대 동작([ADR-006](adr-006-gateway-recheck-policy.md), 조직 indexer·직접 RPC 폴백을 켜지 않은 본선 구성 기준). 장면 하네스는 운영사 엔드포인트를 실제로 끊은 상태(소켓을 끊는 로컬 스위치)에서, 하네스 프로세스 안에서 Gateway 라이브러리의 `getAdmission`을 직접 호출해 Gateway A 행을 확인한다(`IN_PROCESS_GATEWAY_LIBRARY_getAdmission`, 폴백은 명시적으로 끄고 캐시 파일은 행마다 지정, 결과 `scenes.operatorOutage.readWrite`). 이 다섯 경우는 모두 테스트가 단언한다. 별도로 실제 Gateway A 프로세스의 실행 중 세션은 장애 직후 다음 호출을 거부하고 세션을 끝낸다. 마지막 열에 행별 확인 수준을 적는다. compose 스택에서는 아직 확인하지 않았다. 실측 결과는 장면 측정 파일에 기록하고 기대와 다르면 그대로 보고한다.

| 상황 | 모드 | 읽기 전용 도구 | 쓰기 도구 | 하네스 확인 |
|---|---|---|---|---|
| 운영사 중단 — Gateway A, 유효한 서명 캐시 있음 | strict | 차단(strict는 캐시를 쓰지 않음) | 차단 | 실측·단언(읽기·쓰기 두 경우, `UNAVAILABLE_FAIL_CLOSED`) + 실제 세션의 다음 호출 거부·세션 종료 |
| 운영사 중단 — Gateway A, 유효한 서명 캐시 있음 | balanced | 허용(캐시, `decisionSource: CACHE`) | 차단(`WRITE_EXTERNAL` 판정으로 채운 쓰기 캐시가 있어도) | 실측·단언(읽기·쓰기 두 경우) |
| 운영사 중단 — Gateway A, 캐시 만료(시계 +31초) | balanced | 차단(`SIGNED_CACHE_EXPIRED`) | 차단 | 읽기는 실측·단언. 쓰기는 기대(캐시와 관계없이 위 쓰기 행과 같은 경로) |
| 운영사 중단 — Gateway B | strict / balanced | 영향 없음(자체 Control API) | 영향 없음 | strict 실행 중 세션의 `tools/call` 성공만 실측·단언. balanced·쓰기는 기대 |
| 서버 정상, 판정만 만료 | strict / balanced | 차단 | 차단 | 기대(하네스 미검증. 기존 Gateway 테스트 범위) |

장면 측정 결과는 `npm run evaluate:consortium-scene`(기본 표본 50)으로 `benchmarks/results/consortium-scene-<sha7>-<timestamp>.json`에 소스 출처(commit, 작업 트리 상태 등)와 함께 남긴다. 스크립트는 작업 트리가 깨끗하지 않으면 결과를 쓰지 않고(`--allow-dirty`로 실행하면 결과에 기록하고 파일 이름에 `-dirty-<소스 해시 8자리>`를 붙인다), 장면 조건(`assertConsortiumReport`)이 하나라도 깨지면 결과를 쓰지 않으며, 기존 파일을 덮어쓰지 않는다. 측정 대상 코드를 불러오기 전에 주변의 `MCPSHIELD_*`·`OTEL_*` 환경변수를 지우고 telemetry를 끈다. 이 값은 로컬 EVM·REPORT FIXTURE 스캐너 대역 기준이며(결과의 `environment` 라벨과 `limitations` 배열에 표시), 실제 Docker 스캔이나 테스트넷 값으로 표시하지 않는다.

**혼동 주의.** 기존 문서의 “93ms”([evaluation.md](evaluation.md))는 안전 fixture의 **스캐너 실행 시간**(과거 스냅샷)이지 Gateway·admission 지연이 아니다. 기존 admission 측정의 `receiptToNextCheckBlockedMs`도 영수증을 받은 직후 1회 검사한 시간이며 폐기 전파 시간이 아니다. 둘 다 위 (a)(b)의 값으로 인용하지 않는다.

100회 표본으로 안정적인 p99나 Production SLO를 주장하지 않는다. 3회 테스트넷 측정은 소수 사례이므로 개별값/범위를 보고하고 견고한 p95처럼 표시하지 않는다. hash 비용·대기시간·실패 요청을 제외했다면 각각 따로 기록한다.

속도는 우선 **측정·공개**가 필수다. 20ms/99.9% 같은 원본 목표를 측정 전 필수 달성 성과로 가져오지 않는다. 반면 알려진 REVOKED의 unsafe allow는 수용 실험에서 **0건**이어야 한다.

### 12.6 평가 산출물

하나의 evidence bundle에 dataset manifest, raw JSON/CSV, 요약 표/그래프, model/provider/date, prompt hash, policy hash, image digest, commit SHA, runtime/hardware, chain/contract, 실행 명령, 오류·SKIP·비용·한계를 묶는다. 원문 민감 정보는 포함하지 않는다. 외부 연구의 성능 수치를 우리 결과로 쓰지 않는다.

---

## 13. 테스트·CI·Release Candidate

### 13.1 재사용할 테스트

| 경로 | 사용할 증거 |
|---|---|
| `tests/security/scoped-prepared.test.mjs` | scoped Node 실제 관찰·probe·판정; 기존 native 실패 원인 확인 |
| `tests/api/prepared-fullcycle.test.ts` | 준비→스캔→독립 검증자→V2→safe 호출/폐기 차단 |
| `tests/contracts/release-registry-v2.test.ts` | 서명·quorum·격리·terminal 상태 |
| `apps/gateway/test/` | prepared 실행·signed admission·drift·폐기·RPC/경합 |
| `apps/dashboard/test/` | API/BFF·한국어 안내·forms·workflow |
| `tests/api/`, `tests/integration/` | DB·권한·작업·멱등성·통합·관측 |
| `tests/integration/consortium-scene.test.ts` (v2.1) | 로컬 EVM에서 두 회사 Control API·두 Gateway의 정상/폐기/운영사 중단/운영사 장악/직접 긴급 격리 장면. 조건은 하네스의 `assertConsortiumReport` 한 곳(표본 5). `npm run test:backend`(CI의 `npm test`)에 포함된다. 아직 CI 실행 결과는 없으며 PR 후 확인한다 |

테스트 파일이 존재한다는 이유만으로 PASS 처리하지 않는다. 실제 실행된 subtest와 조건부 SKIP을 확인한다.

### 13.2 네 종류의 검증을 분리

1. **빠른 로컬 검사:** 타입·unit·schema·replay. 개발 feedback용.
2. **Linux/Docker 필수 통합:** 실제 격리·준비·검증자·local chain·두 Gateway. secret 없이도 실행 가능한 회귀 검사.
3. **승인된 실환경 검증:** 실제 모델과 Base Sepolia. 비용/키가 있어야 하며 fork PR에 secret을 제공하지 않음.
4. **브라우저·발표 검수:** 실제 화면 조작·링크·PPT/PDF·영상·clean 환경 재현.

CI의 합성 모델 응답은 provider 계약 검사이지 실제 모델 품질 증거가 아니다. 테스트넷/실제 모델을 모든 PR에서 반복 호출할 필요는 없다. 승인된 release 검증으로 분리하되 **같은 RC 코드·정책·이미지·dataset**의 증거를 연결한다.

### 13.3 RC 통과 조건

- §5 P0 41개가 각각 증거와 연결되어 완료 판정됨.
- 관련 required CI가 동일 RC SHA에서 성공하고 필수 native 검사가 SKIP되지 않음.
- non-gating/P1 SKIP은 이유를 적고 required 실패를 녹색으로 숨기지 않음.
- 원인 미해결인 현재 실패를 단순 skip/expectation 변경으로 통과시키지 않음.
- 깨끗한 Linux 환경에서 local E2E **10/10 연속 성공**.
- 테스트넷은 §12.5의 실제 사례를 별도 확인. 10회 전부 외부 체인·모델 호출일 필요 없음.
- safe 업무와 bad 차단, 변조·stale·timeout·drift의 실패 경로를 확인.
- 수정 담당자가 아닌 사람이 리뷰하고 보안상 머지 차단 문제를 해소.
- 실제 키·PII·불필요한 payload가 공개 산출물에 없음.

### 13.4 머지와 배포

기존 `master/main`을 통합 기반으로 사용하고 원본 `mcp/main`·공개 합성 데모는 보존한다. PR을 리뷰하고 검증 후 머지한다. 새 문서 작성은 PR 머지·배포 승인이 아니다.

공개 웹에 scanner host 권한을 추가하지 않는다. 실제 Linux worker·validator·DB와 공개 체험을 구분한다. 배포 변경은 대상 서비스·이전 이미지/설정·데이터 호환성·되돌릴 방법을 기록한 뒤 승인된 범위에서 수행한다.

---

## 14. 현재 구현 상태 — 역사적 증거와 새 완료 기준 분리

아래는 작성 시 확인한 코드와 **2026-09-19 감사**의 재사용 판단이다. 이번 문서 작성 중 전체 테스트·공개 배포·실환경 평가를 재실행한 것은 아니다.

| 영역 | 현재 기반 | 캡스톤에서 먼저 확인할 잔여 |
|---|---|---|
| Identity/Scanner | source·closure·prepared·Static/AI/Sandbox 코드 존재 | scoped-v2 native 2건의 ABSTAIN 원인 수정·동일 SHA 재검증 |
| Publisher | 기존 UI/MOCK 표시는 있음 | 실제 게시자 서명 fixture·검증은 최소 신규 작업 |
| Trust | V2·EIP-712·quorum·Indexer·local EVM 검사 존재 | Base Sepolia의 실제 배포/거래/전파 증거 |
| Gateway | stdio/HTTP·prepared·signed admission·drift 코드 존재 | 주력 Node 프로필의 실제 LLM Agent 연결·통합 검수 |
| Backend/화면 | SQL 큐·권한·console·로그·health 존재 | chain retry 상한 등 핵심 운영 경계와 실제 브라우저 검수 |
| 평가 | fixture 반복·단일 턴 harness 존재 | 독립 holdout·no-AI 기준선·Full Gateway ASR·정상 업무 성공률 |
| 제출 | HTML·가이드·기존 발표 자료 존재 | 현재 RC에 맞는 실제 PPT/PDF·영상·clean 재현 |

기존 전체 감사: [MASTER_REQUIREMENTS_AUDIT_2026-09-19.md](MASTER_REQUIREMENTS_AUDIT_2026-09-19.md). 거기의 FAIL/SKIP를 삭제하지 않고 후속 성공 증거를 별도로 추가한다. 이전 10회 데모 성공은 새 프로필·새 RC의 성공을 대신하지 않는다.

### 14.1 2026-10-11 기준 추가 상태 (v2.1)

위 표는 2026-09-19 감사 기준이며 그대로 둔다. 아래는 1차 멘토링(2026-10) 이후 이번 변경 기준이다.

| 영역 | 지금 있는 것 (이번 변경 포함) | 다음 단계 (아직 아님) |
|---|---|---|
| 운영사 비신뢰 장면 | `tests/integration/consortium-scene.ts` 하네스: Ganache 로컬 EVM에 V2 배포(owner 계정 0, 검증자 계정 1~3), 운영사 Control API(자체 Ed25519 키·V2 relayer·체인 조회), 회사 B Control API(별도 SQLite·자체 키·자체 체인 조회, relayer 없음), Gateway A용 운영사 엔드포인트의 정직/중단/장악 3가지 모드(중단 = 소켓을 끊는 로컬 스위치, 장악 = 운영사 admission 서명 키·키 ID·테넌트 토큰을 쥔 공격자 API가 조작된 체인 뷰로 서명) | 같은 장면의 Base Sepolia 반복 |
| 장면 검증 | `consortium-scene.test.ts`(조건은 `assertConsortiumReport`): ① 정상 v1.0.0(2-of-3 PASS): A·B Gateway 자식 프로세스 `inspect` ALLOW, 실제 MCP stdio `tools/call`(`list_messages`)이 A 경유·B 경유·직접 모두 성공 ② 운영사 중단: A의 실행 중 세션은 다음 호출 거부 후 세션 종료, B 세션 계속, 읽기/쓰기 5개 경우(§12.5) ③ 악성 v1.0.1 격리 + 2-of-3 FAIL → REVOKED → A·B Gateway `run` 명령이 종료 코드 3·REVOKED로 끝나 후보 spawn 전에 거부(`refusedBeforeSpawn`). 이때 A의 `run`이 남긴 로컬 폐기 기록을 장면 ④의 "기록한 A"가 사용 ④ 운영사 admission 서명 키 장악(체인은 계속 REVOKED): 폐기를 본 적 없는 새 A는 위조 ALLOW(대조군), 폐기를 기록한 A는 BLOCK(`LOCAL_REVOCATION_JOURNAL`), B는 BLOCK REVOKED ⑤ 검증자 C가 체인에 직접 낸 긴급 격리 후, 이미 열린 A·B 세션이 다음 호출을 거부(단언: 거부 이유에 `QUARANTINED` 포함, 영수증 확인 뒤 시작한 호출의 허용 0건, 전송 전 예상 밖 실패 0건. 실측 이유 `RELEASE_QUARANTINED (QUARANTINED)`). 거부까지 걸린 시간은 측정값이며 단언 대상이 아님 | compose·대시보드에서 같은 장면 재현 |
| 측정 | `scripts/ops/evaluate-consortium-scene.ts`(`npm run evaluate:consortium-scene`, 기본 표본 50): (a) 호출당 지연(공식 측정 `f85f8e8` p50: 직접 0.24 / A 62.87 / B 61.69 ms) (b) 전파 시간(A·B 각 126 ms) (c) 장애 시 읽기/쓰기 결과를 JSON으로 기록. 조건 실패·깨끗하지 않은 작업 트리(`--allow-dirty` 없이)에서는 결과를 쓰지 않고 기존 파일을 덮어쓰지 않음 | 깨끗한 트리의 공식 측정값, 테스트넷 값, 실제 Docker 스캔 포함 값 |
| 결정 기록 | ADR-003~007, [멘토링 대응 문서](mentoring-2026-10-response.md) | 결정의 배포 반영(compose V2 이전 등). 멀티시그·타임락·참여 보상은 Roadmap |
| 저장소 | GitHub 기본 브랜치를 `master/main`으로 변경 | — |
| 실행 스택 | 기본 compose는 여전히 V1·레거시 무서명 `/api` | compose V2 두 회사 스택(회사 B API 서비스, 양쪽 서명 모드, probe·대시보드 수정) |
| 실제 AI | 검증자별 AI 설정 코드 존재 | 실제 모델 연결 실증(CAP2-102, CAP2-306) |

이번 장면의 한계: **LOCAL_EVM(Ganache)** 이며 Base Sepolia가 아니다. 스캐너는 명시적인 **REPORT FIXTURE 테스트 대역**이며 이 하네스에서 Docker 스캔을 하지 않는다. 두 회사가 같은 로컬 RPC를 쓴다. 검증자 서명은 팀이 운영하는 테스트 키다. 장면 하네스의 검증자는 운영사 API가 준 서명 템플릿에 그대로 서명하며 독립 재검사(`prepared-verification`)를 거치지 않으므로 CAP2-202(독립 검증)의 증거가 아니다. 컨소시엄 운영에서는 검증자가 운영사 템플릿이 아니라 자체 재검사 결과에 서명해야 한다. 로컬 체인은 즉시 블록을 만들므로 전파 시간은 하한값이다. compose·대시보드와는 아직 연결되지 않았다. 결과 JSON은 이 한계를 `environment`(`chain: LOCAL_EVM_GANACHE`, `scanner: REPORT_FIXTURE_TEST_DOUBLE`, `validators: SINGLE_INSTITUTION_DEMO`, `governance`(배포 결과 값), `validatorVerification: SIGNS_OPERATOR_TEMPLATE_NO_INDEPENDENT_RESCAN`, `rpc: ONE_SHARED_LOCAL_RPC_FOR_BOTH_COMPANIES`)와 `limitations` 배열로 함께 남긴다.

요구사항별 위치: 장면 ③은 CAP2-302의 **폐기 사례**에 대한 Gateway CLI 수준의 실행 전 거부 증거(로컬 EVM)다. 종료 코드 3은 코드상 spawn 전 차단 경로에서만 나온다(후보 실행 횟수를 직접 세지는 않는다. 종료 코드 3과 stderr의 차단 판정이 spawn 이전 경로에서만 나온다는 코드 근거에 기댄 간접 증거이며, §10.1의 "후보 entrypoint 실행 0건" 직접 증거(실행 표식·프로세스 기록)는 이 하네스가 남기지 않으므로 별도로 확보한다). 변조·불명확 릴리스 사례와 테스트넷은 별도다. 장면 ⑤는 CAP2-307의 "같은 chain tx 이후 각 차단 시각과 이유"에 대한 로컬 EVM 증거이며 긴급 격리에 한정된다(2-of-3 FAIL 폐기의 실행 중 세션 전파는 미측정). 따라서 이 결과만으로 CAP2-205(테스트넷), CAP2-302, CAP2-307, CAP2-308(테스트넷 반복 포함)을 완료로 표시하지 않는다.

**현재 CAP2 완료율: 미산정.** 기존 기능을 위 41개에 매핑한 후 실제 증거를 확인해야 한다. 문서만 새로 썼다고 완료율을 올리지 않는다.

---

## 15. Main + 3파트 운영

| 역할 | 소유 작업 | 캡스톤 산출물 |
|---|---|---|
| Main | 범위·공통 인터페이스·통합·증거 ledger·리뷰 조율 | P0 검수표, RC manifest, 통합 결과·최종 보고 |
| Security·AI | 기존 resolver/scanner·fixture·probe·평가 | native 실패 수정, 서명 fixture, 실제 분석·holdout 결과 |
| Blockchain·Backend | 기존 API/SQL/Validator/Contract/Indexer | 독립 검증·retry 경계·테스트넷 및 projection 증거 |
| Frontend·Gateway·운영 | 기존 Gateway/Agent 연결/UI·재현 구성 | 실제 정상 작업·A/B 차단·화면·영상·실행 가이드 |

Reviewer는 별도 상시 서비스가 아니라 읽기 전용 역할로 운영한다. 핵심 보안 경계는 작성자가 아닌 사람이 검토한다. Main은 모든 파트의 기능을 대신 재작성하지 않는다.

기존 worktree의 미완료 변경은 보존한다. 새 작업은 최신 검증된 통합 기준에서 필요한 변경만 가져오며, 브랜치 전체를 무검토 머지하지 않는다. 기존 경로 소유권을 따르고 interface/schema 변경은 Main이 먼저 조율한다.

---

## 16. 구현 순서 — 기존 결과를 완성하는 순서

인원·마감일이 확정되지 않았으므로 임의의 완료 날짜를 약속하지 않는다. 아래는 선후관계와 종료 조건이다.

v2.1에서는 체인이 필요한 장면(CAP2-308)을 먼저 실증하기 위해 **체인 확인 Gateway와 테스트넷을 앞으로 당기고**, compose를 V2로 옮기는 단계를 추가했다.

| 단계 | 할 일 | 기존 자산 | 종료 조건 |
|---|---|---|---|
| A. 범위/환경 고정 | CAP2 매핑·Node 프로필·실행 버전·키/비용·Linux 환경 확인. 본선 경로 고정(§2.4) | 감사·handoff·기존 설정, ADR-003~007 | 미지원/외부 의존 목록과 재사용 경로 확정. 결정 기록은 2026-10-11 완료 |
| B. 체인 확인 Gateway 장면(로컬 EVM) | 회사 B 자체 Control API + Gateway B, 운영사 중단·장악 장면, (a)(b)(c) 측정 | 기존 `apps/api`·Gateway 서명 admission·V2 조회기 | 장면 테스트가 CI에서 통과, 측정 JSON 생성. 하네스는 `9c7bc9d`에서 추가(로컬 통과), 깨끗한 트리 공식 측정은 `f85f8e8`에서 완료([결과](../benchmarks/results/consortium-scene-f85f8e8-2026-10-10T18-00-42-747Z.json)), CI 결과 확인 남음 |
| C. Base Sepolia 반복 | V2 배포·정상 승인·폐기 tx, B 장면과 전파 측정을 테스트넷에서 반복 | 기존 V2 배포 코드 | CAP2-205 증거 묶음과 CAP2-308 테스트넷 반복 기록 |
| D. compose·대시보드 V2 이전 | compose 계약 초기화를 V2로 교체, 회사 B API 서비스 추가, 두 Gateway 서명 모드, startup probe·대시보드 live 화면 수정, compose 테스트 갱신 | 기존 Compose·Dockerfile·대시보드 | `docker compose`로 두 회사 스택이 뜨고 화면에서 A/B 차이가 보임 |
| E. 핵심 실패 수정·병렬 보완 | scoped-v2 증거/권한/설정 원인 추적; S: 게시자 서명·holdout·실제 AI; F: 실제 Agent·기존 UI 연결 | scanner/API/validator native 테스트, fixture/harness/components | 실제 malicious FAIL과 safe PASS, Linux 통합 성공, 모듈별 실제 증거 |
| F. 하나의 흐름으로 통합 | source→scan→quorum→testnet→A/B 차단 및 safe 업무 | prepared fullcycle, 장면 하네스 | 같은 identity/정책/RC의 end-to-end 기록 |
| G. 측정·재현 | 5비교군(방법별 기여 분리)·실제 Agent·latency·전파·clean 환경 | 기존 benchmarks/CI | 원자료·한계 포함 평가 보고 |
| H. 동결·발표 | P0 검수, 10회 local 데모, PPT/PDF·영상·링크 | 기존 pitch/guide | §13 RC 조건과 §17 증거 목록 완결 |

B~D와 E는 병렬로 진행할 수 있다. E가 막혀도 문서·데이터 라벨·비밀 없는 설정 준비는 계속한다. 반대로 잘못된 통합 판정 위에서 평가 숫자나 영상을 확정하지 않는다. 후속 멘토링(컨트랙트 상세)에서는 gas 비용, 키 교체 구현, 정책 버전 관리를 다룰 수 있도록 C 단계의 실측 자료를 준비한다.

### 16.1 새로 만드는 부분의 상한

원칙적으로 새 작업은 **게시자 서명 fixture/검사, 부족한 평가 표본·결과 묶음, 기존 Agent harness의 Gateway 연결, 운영사 비신뢰 장면 하네스(v2.1), 제출용 최종 산출물**에 집중한다. 나머지는 기존 함수·설정·테스트의 수정이다. 이 밖의 새 서비스/프레임워크가 필요하다고 판단되면 범위 변경으로 검토한다.

### 16.2 외부 의존과 승인

| 의존성 | 준비할 것 | 없을 때 처리 |
|---|---|---|
| Linux Docker | 신뢰된 실행 호스트·고정 builder/image·저장소 권한 | native 검증 미완료. host 실행 fallback 금지 |
| 실제 모델 | 사용할 모델·키·전송 허용 입력·호출/비용 상한 | provider 계약 검사까지만 진행, 실제 AI 검증 미완료 |
| Base Sepolia | 테스트 전용 deployer/validator 키·RPC·test gas·Explorer 확인 | local EVM 증거만 확보, CAP2-205 미완료 |
| 공개 배포 | 대상 서비스·비용·권한·롤백 승인 | 기존 공개 데모 보존; 로컬/녹화 실증 준비 |
| 발표 규격 | 학과의 제출 형식·시간·분량 | §18 기본안 사용 후 실제 규정에 맞춰 편집 |

키는 채팅으로 요청하거나 출력하지 않는다. 외부 의존이 없다고 목표를 mock 성공으로 재정의하지 않는다. 비용 상한 도달 시 관련 호출을 멈추고 진행한 증거와 남은 조건을 보고한다.

---

## 17. 증거 ledger와 완료 판정

### 17.1 행 단위 기록 형식

각 `CAP2-*`에 다음을 기록한다. 기존 audit 파일은 과거 기록으로 두고 새 검수 결과와 섞지 않는다.

| 필드 | 의미 |
|---|---|
| ID / 담당 | §5의 요구사항과 소유자 |
| 상태 | 완료 / 부분 / 미완료 |
| 기존 코드 / 변경 유형 | 경로와 R/C/F/N |
| 검증 기준 | 행의 조건과 연결된 본문 범위 |
| 실행 근거 | commit SHA·명령·환경·시간·raw 결과 위치 |
| 실제 결과 | PASS/FAIL/SKIP/NOT_RUN, 실패 이유 |
| 실환경 근거 | 필요한 모델·chain·Agent·브라우저 증거 |
| 검토자 | 작성자 외 검토자의 확인과 남은 이슈 |

완료는 조건 전체가 실제 증거로 확인된 상태다. 일부 코드/시험만 있거나 외부 실증이 없으면 부분, 근거가 없으면 미완료다. SKIP은 PASS가 아니다.

```text
엄격 완료율 = 완료 CAP2 수 / 41 × 100
착수 범위 = (완료 + 부분) / 41 × 100
```

v2.1부터 분모는 41이다(CAP2-308 추가). v2.0 기준(분모 40)으로 계산한 과거 값이 있으면 그대로 옮기지 않고 기준 버전을 함께 적는다.

이는 요구 충족률이지 코드량·남은 작업 시간의 비율이 아니다. 각 행의 크기가 다르므로 일정 추정에는 그대로 사용하지 않는다.

### 17.2 최종 evidence bundle

다음은 **앞으로 만들어 채울 산출물 목록**이며 현재 존재/완료 선언이 아니다. 기존 유효한 로그·결과는 재사용하고 SHA·환경 차이를 적는다.

| 산출물 | 최소 내용 |
|---|---|
| RC manifest | 코드 SHA, 의존성 lock hash, 이미지, 정책, dataset, 모델, chain/contract |
| CAP2 ledger | 41개 완료/부분/미완료와 근거 링크 |
| CI/native 결과 | 필수 step/subtest, PASS/FAIL/SKIP, 10회 local 반복 결과 |
| Publisher 증거 | safe/bad 서명 검증과 변조·다른 키 거부 |
| Trust 증거 | 검증자별 확인/서명, 실제 tx/event 및 projection |
| Gateway/Agent 증거 | safe 실제 도구 호출, A/B 후보 start 0건, drift/후속 차단 |
| 운영사 비신뢰 증거 (v2.1) | 장면별 A/B 판정·이유·체인 실제 상태, 호출당 지연·Gateway별 전파·장애 시 읽기/쓰기 결과(LOCAL_EVM과 테스트넷 분리) |
| 평가 묶음 | 표본 manifest·raw 결과·5비교군·ASR/정상 업무·latency·비용 |
| 재현 문서 | 필요한 권한·버전·정확한 명령·예상 결과·정리/복구 |
| 발표 묶음 | 열리는 PPTX/PDF, 3분 영상, GitHub/Explorer 링크, 한계/출처 |

이미지·영상만으로 수치나 내부 차단을 증명하지 않는다. 로그/trace/manifest와 연결한다. 재현에 필요한 synthetic fixture는 제공하되 실제 공격 인프라나 민감 payload를 포함하지 않는다.

---

## 18. 시연과 발표

### 18.0 도입 — 실제 사건으로 시작한다 (v2.1)

발표와 영상은 실제 사건 한 문장으로 연다. **2025년 9월, npm의 메일 발송용 MCP 서버 패키지 `postmark-mcp`의 한 업데이트가 보내는 모든 메일을 외부 주소로 몰래 숨은 참조(BCC)하도록 바뀐 사례가 보고되었다.** 정상 기능은 그대로 둔 채 업데이트로 데이터를 빼돌린다는 점에서 우리 메일 MCP 시나리오와 거의 같은 구조다.

이 사건은 외부에 보고된 사례를 문제 설명에 쓰는 것이며, MCPShield가 그 사건을 탐지했다고 주장하지 않는다. 우리 데모는 실제 발송 없이 합성 메일 조회와 합성 canary로 같은 구조(정상 기능 + 몰래 유출)를 재현한다.

### 18.1 3분 영상 기본안

| 시간 | 보여줄 것 | 핵심 메시지 |
|---|---|---|
| 0:00–0:15 | 2025-09 `postmark-mcp` 사건 한 문장 | 정상 업데이트처럼 보이는 위험은 실제로 일어났다 |
| 0:15–0:30 | AI의 합성 메일 조회 성공 | 정상 업무는 계속 된다 |
| 0:30–0:50 | 같은 게시자가 서명한 악성 업데이트, 격리 OFF 실험 | 정상 서명만으로 행동 안전을 알 수 없다 |
| 0:50–1:15 | Static/AI/Sandbox evidence | 검사 근거가 있다 |
| 1:15–1:35 | 검증자·2-of-3·체인 tx(LOCAL_EVM/테스트넷 표시) | 판정을 공동 상태로 기록한다 |
| 1:35–1:55 | Gateway A/B 차단, 후보 start 0건 | 기록이 실제 실행 권한으로 이어진다 |
| 1:55–2:25 | **운영사 장악 장면**: 운영사 서명이 위조되자 폐기를 본 적 없는 A는 ALLOW(대조군), 폐기를 기록해 둔 A는 그 기록으로만 BLOCK, B는 체인을 보고 BLOCK REVOKED, 체인 실제 상태 REVOKED. 운영사 중단 시 A 정지·B 계속 | 운영사를 믿지 않아도 집행된다 — 체인이 필요한 이유 |
| 2:25–2:45 | 비교 평가·정상 작업 성공률·호출당 지연·전파 시간 | 효과와 비용을 측정했다 |
| 2:45–3:00 | 지원 범위·한계·결론 | 모든 MCP 안전 인증은 아니다 |

운영사 장악 장면은 현재 로컬 EVM 장면 하네스로 재현한다. 테스트넷·compose 화면으로 다시 찍기 전까지는 화면에 LOCAL_EVM·REPORT FIXTURE 표시를 남긴다.

3분은 편집 영상 길이다. 수분 걸리는 scan과 거래 확인을 3분 내 실시간 완료한다고 약속하지 않는다. 컷 편집·사전 실행·녹화·REPLAY는 표시하고 원본 trace/tx에 연결한다.

### 18.2 발표자료 기본 10장

1. 문제: 정상 업무처럼 보이는 위험한 도구 업데이트(2025-09 `postmark-mcp` 사건으로 시작).
2. 보호 대상·지원 범위: 합성 메일 조회, Linux/Node 프로필.
3. 해결 흐름: 검사 → 공동 판정 → 실제 차단. 차별점 한 줄(업데이트마다 재검증·실행 전 강제·다기관 판정).
4. 기존 구현 재사용 아키텍처와 기술 선택: 검증 흐름 / 실행 통제 흐름 두 그림과 Gateway별 판정 조회 경로(§4.1).
5. AI의 역할과 no-AI 기준선 비교.
6. **블록체인 필요 조건 한 장**: 세 조건(서로 불신·중립 운영자 없음·참여 이유)과 MCPShield의 답(컨소시엄), 체인 없이는 깨지는 장면(운영사 장악·중단 시 A/B 차이), “운영사 + 투명성 로그”와의 비교 한 줄(§9.1).
7. 정상/악성 E2E·게시자 서명·두 Gateway 증거.
8. 평가 결과·정상 업무 성공률·지연·비용.
9. 구현/검증 범위·재현·실패 처리.
10. 한계·팀 기여·Roadmap·코드/Explorer 링크.

기존 HTML pitch를 편집 기반으로 사용한다. HTML만으로 PPTX/PDF 제출 완료라고 하지 않는다. 학과 규정이 다르면 분량·표지 포함 기준을 조정한다.

### 18.3 현장 fallback

- RPC 장애: 실제 성공 때의 tx와 서명/로그를 보여주되 현재 상태 조회 성공처럼 표시하지 않는다.
- 모델 장애: 녹화/REPLAY를 명시한다. 오류를 PASS로 대체하지 않는다.
- Docker 장애: 실행을 중단하고 보존된 증거를 보여준다. host에서 후보를 실행하지 않는다.
- 전체 장애: 3분 영상과 RC evidence bundle을 사용한다. 이는 현장 live 실패를 없애는 것이 아니다.

---

## 19. 심사 질문·위험·과장 방지

| 질문/위험 | 답변 및 처리 |
|---|---|
| 결국 package scanner 아닌가? | 탐지뿐 아니라 exact runtime 승인·폐기 상태와 실제 Agent 실행 권한을 연결한다. 업데이트마다 재검증하고, 실행 전에 Gateway에서 강제하며, 여러 기관의 판정을 공동 기록으로 묶는다 |
| DB로 충분하지 않나? | 단일 조직은 가능하다. 서로 다 믿지 않는 여러 회사가 같은 판정 규칙을 공유하기 위해 체인을 선택했다. 체인을 자기 API로 확인하는 회사(B)는 운영사의 admission 서명 키가 장악돼도 폐기 릴리스를 차단하고, 운영사가 멈춰도 정상 릴리스를 계속 쓰는 것을 로컬 EVM에서 확인했다(운영사 중단 중 폐기 릴리스 차단은 설계상 같은 경로지만 하네스가 따로 확인하지 않았고, 테스트넷 반복은 다음 단계, §9.1) |
| 블록체인이 안전성을 보장하나? | 아니다. 증거 검증이 잘못되면 잘못된 판정이 기록될 수 있다 |
| 검증자는 왜 참여하나? | “쓰는 회사가 곧 검증자”다. 각자 해야 하는 업데이트 검사 비용을 나누고, 기여한 회사만 조기 경보·판정 근거 원문(보고서·증거)을 받는다(VirusTotal 기여형과 같은 방식). 체인의 상태·투표 기록은 공개라 혜택이 아니다. 수수료는 이후 확장이며 서명 건당 보상은 쓰지 않는다. 데모의 3개 키는 팀이 운영한다(§9.1, ADR-003) |
| 투명성 로그로 충분하지 않나? | 회사 쪽 검증까지 제대로 갖추면 상당 부분 대신할 수 있고, 참여자가 한 곳이면 그쪽이 더 싸다. 체인을 쓰는 이유는 회사마다 다른 답을 사후 탐지가 아니라 구조로 막고, 정족수·폐기 불가역 규칙을 회사마다 따로 구현하지 않고 공동 컨트랙트가 집행하게 하며, 운영사가 멈춰도 각 회사가 직접 읽게 하기 위해서다. 이 이점은 회사가 체인을 직접 확인할 때만 생긴다(§9.1) |
| owner 키가 털리면? | REVOKED를 VERIFIED로 되돌릴 수 없다. 즉시는 투표를 쓸 수 없고, 즉시 가능한 최악은 검증자 disable·정책 deprecate로 모든 승인을 만료시키는 서비스 거부(fail-closed)다. 1일 지연 뒤에는 검증자 교체로 아직 폐기되지 않은 릴리스에 거짓 VERIFIED를 만들 수 있으나, 교체 예약은 체인 이벤트로 공개되고 Gateway는 고정한 검증자 집합 버전이 바뀌면 재설정 전까지 차단한다(§9.5). MVP는 단일 키(운영사 relayer 키와 같음)임을 공개하고, 운영은 멀티시그 재배포·relayer 분리·타임락을 계획한다(ADR-007) |
| 운영사 DB를 바꾸면? | admission의 거짓 ALLOW는 나오지 않는다. 운영사 API는 요청마다 체인을 읽고 체인 상태로 서명하며, DB를 바꾸면 차단(불일치·상태불명)이 될 뿐이다. 영향은 화면 표시 변경과 차단(서비스 거부)이다. 검증자 서명 템플릿도 DB의 검사 결과로 만들어지므로 검증자는 독립 재검증해야 한다(§9.2). 현실적 위협은 운영사 admission 서명 키 장악이며, 이때 운영사만 믿는 A는 자기가 직접 보지 못한 폐기에 대해 속고 자기 API로 체인을 보는 B는 막는다(§9.1, CAP2-308) |
| 같은 AI를 쓰면 독립적인가? | 아니다. 기관이 달라도 같은 스캐너·같은 모델이면 오류가 함께 난다. 검증자별로 다른 AI 모델·검사 환경을 쓸 수 있게 코드가 열려 있지만, 같은 검증 코드를 쓰는 한 상관 오류 위험은 남는다(§9.2) |
| AI가 없어도 되는가? | Static+Sandbox와 Full을 비교해 기여를 측정한다. 개선이 없으면 그 결과도 공개한다 |
| 정상 도구도 막히지 않나? | 보류와 악성 판정을 구분하고 정상 업무 성공률·차단률을 함께 제시한다 |
| 세 키가 모두 같은 팀 소유 아닌가? | 맞다. quorum 프로토콜 실증이며 다기관 탈중앙 운영 완성은 아니다. 실제 운영에서 한 주체가 3개를 다 가지면 서명 3개 달린 중앙 DB와 같다 |
| runtime drift가 모든 악성 행동을 잡나? | 아니다. 도구 표면 변경을 탐지하며 표면이 같은 내부 악성 행동은 놓칠 수 있다 |
| 이미 실행 중인데 폐기되면? | 다음 호출부터 막는다. 이미 보낸 메일·이미 발생한 유출은 되돌리지 못하며 idle process 즉시 종료를 보장하지 않는다 |
| Gateway를 우회하면? | 보호 경계 밖이다. Gateway를 거치지 않고 MCP를 직접 연결하면 통제할 수 없다. endpoint 강제 관리·기업 배포 통제는 Roadmap이다 |
| Gateway 때문에 느려지지 않나? | 호출마다 승인 상태를 확인하므로 지연이 더해진다. 직접 호출 대비 A/B 경유 지연을 측정해 공개한다(로컬 공식 측정 p50: 직접 0.24 ms, Gateway 경유 약 62 ms, §12.5). 기존 “93ms”는 스캐너 시간이라 이 질문의 답으로 쓰지 않는다 |
| 실제 메일/CRM에 바로 쓰나? | 아니다. 이 캡스톤은 합성 데이터와 제한된 실행 프로필의 실증이다 |
| Sandbox escape/time bomb은? | 완전 방어를 주장하지 않는다. 최소 권한·격리·시간 제한과 지원 범위를 공개한다 |
| 정상 서명은 npm 공식 인증인가? | synthetic 테스트 게시자 서명이다. npm provenance와 구분한다 |
| 성능이 기대보다 낮으면? | 기능을 숨기지 않고 실측과 실패 원인·한계를 보고한다. 일반 안전성을 과장하지 않는다 |

사용 금지 표현: “모든 MCP 안전 인증”, “100% 악성코드 탐지”, “완전 탈중앙화”, “AI가 안전을 확정”, “준비 상태 READY이므로 실행 허용”, (v2.1) “모든 Gateway가 운영사 없이 동작”(A는 운영사에 의존), “테스트넷에서 장악 장면 검증 완료”(현재는 LOCAL_EVM), “독립된 3개 기관이 검증”(데모는 팀 운영).

권장 표현: **“정해진 정책과 시험 환경에서 위험 증거를 확인하고, 미검증·변조·폐기된 릴리스의 실행을 Gateway 경로에서 제한한다.”**

프로젝트 이름과 동일한 `MCPShield` 연구가 이미 존재한다. 제출 시 부제 **“Release Firewall: 검증된 릴리스만 실행하는 MCP 보안 Gateway”**를 붙이고 선행연구와 구분한다. 동일 명칭이나 기능 최초성을 근거 없이 주장하지 않는다. [동명 연구](https://arxiv.org/abs/2602.14281)

(v2.1) MCP 서버 목록 사이트에도 같은 이름의 스캐너가 여럿 있다. 이름은 유지하되 표지·README 첫 줄에 차별점 한 줄(**업데이트마다 재검증·실행 전 강제·다기관 판정**)을 함께 쓴다(§1.2).

---

## 20. 장기 Roadmap — 캡스톤 분모에서 제외

1. **지원 확대:** PyPI·다른 언어·macOS/Windows enforcement·private registry·원격 서버 assurance.
2. **격리 강화:** gVisor/microVM/WASI·TEE·강한 syscall 관찰·secret broker.
3. **공급망 연계:** Sigstore/SLSA·registry/IDE 통합·표준화된 assurance 표시.
4. **분산 신뢰:** 독립기관 validator·운영 거버넌스·HSM/KMS·멀티체인. (v2.1) 참여 회사마다 **자체 체인 노드** 또는 여러 RPC 제공자를 써서 RPC 제공자가 새로운 단일 실패 지점이 되지 않게 한다.
5. **기업 운영:** stage별 큐·autoscaling·replica/sharding·multi-region·PITR·장기 SLO·실제 알림 운영. Gateway 우회를 막는 endpoint·배포 통제.
6. **(v2.1) 참여 설계:** 검증 기여에 대한 보상·평판(악성 업데이트를 잡아낸 공개 기록), 게시자·Gateway 사용 기업이 내는 검증 수수료. 보상·제재는 다시 확인 가능한 증거에만 연결하고 서명 건당 보상은 쓰지 않는다. 그 전제로 **재현 가능한 증거 형식과 이의 제기(appeal) 절차**를 만든다([ADR-003](adr-003-validator-consortium.md)).
7. **(v2.1) 관리자 권한 강화:** 멀티시그 관리자로 컨트랙트 재배포(owner와 relayer 키 분리), deprecate·register에는 **타임락**, disable은 키 유출 대응용이라 짧은 지연 또는 멀티시그 정족수로 제한하는 다음 컨트랙트 버전, 키 장악 시 긴급 절차([ADR-007](adr-007-registry-owner-governance.md)).

지금 만들지 않는다는 뜻이지, 이미 작성된 관련 코드를 삭제하라는 뜻은 아니다. 원본 마스터의 장기 요구사항과 감사 기록에 연결해 보존한다.

---

## 21. 캡스톤 v1.0 요구사항과의 추적표

v1.0 §18의 CAP-FR P0는 34개다. 아래는 **모든 기존 P0 ID**의 유지/분해/이관 관계다. 새로운 이름으로 번호만 바꿔 완료 처리하지 않는다.

| v1.0 CAP-FR | v2.0 연결 | 결정 |
|---|---|---|
| CAP-FR-001 | CAP2-001, P1 OCI | npm/tarball 주력; OCI 필수 범위 축소 |
| CAP-FR-002 | CAP2-001, CAP2-002 | mutable 입력 고정과 runtime 결합 명확화 |
| CAP-FR-003 | CAP2-002, CAP2-006 | 원본/실행 digest 구분 |
| CAP-FR-004 | CAP2-003 | 유지 |
| CAP-FR-101 | CAP2-101 | 유지 |
| CAP-FR-102 | CAP2-103, CAP2-005 | baseline·semantic diff 유지 |
| CAP-FR-103 | CAP2-101 | 유지 |
| CAP-FR-104 | CAP2-101, P1 고급 SBOM | 최소 dependency/install 변화 필수, 범용 플랫폼 제외 |
| CAP-FR-105 | CAP2-102 | 실제 provider·입력 경계 증빙 명시 |
| CAP-FR-106 | CAP2-104 | 유지 |
| CAP-FR-107 | CAP2-104 | 유지 |
| CAP-FR-108 | CAP2-104, CAP2-105 | 유지 |
| CAP-FR-109 | CAP2-105, CAP2-108 | 관찰 지원 범위 명시 |
| CAP-FR-110 | CAP2-105, CAP2-107 | evidence binding·판정 우선순위 명확화 |
| CAP-FR-111 | CAP2-107 | 유지 |
| CAP-FR-201 | CAP2-006, CAP2-201, CAP2-207 | identity/policy/evidence 결합 유지 |
| CAP-FR-202 | CAP2-201, CAP2-202 | 서명과 독립 검증 구분 |
| CAP-FR-203 | CAP2-201 | 유지 |
| CAP-FR-204 | CAP2-203 | 유지 |
| CAP-FR-205 | CAP2-203 | 유지 |
| CAP-FR-206 | CAP2-204 | TTL·해제/만료의 실행 정책 보완 |
| CAP-FR-207 | CAP2-204 | 유지 |
| CAP-FR-208 | CAP2-205, CAP2-206 | 배포+실제 전파 증거로 명확화 |
| CAP-FR-301 | CAP2-301, CAP2-306 | SDK client와 실제 Agent 구분 |
| CAP-FR-302 | CAP2-302 | 유지 |
| CAP-FR-303 | CAP2-302, CAP2-305 | 승인 유효성·freshness 포함 |
| CAP-FR-304 | CAP2-305 | strict 기본 경계 고정 |
| CAP-FR-305 | CAP2-303, CAP2-304 | 초기 표면과 후속 호출 검사 구분 |
| CAP-FR-306 | CAP2-403 | 기존 메시지/로그 재사용 |
| CAP-FR-401 | CAP2-403 | 유지 |
| CAP-FR-402 | CAP2-404 | 기존 화면 재배치 우선 |
| CAP-FR-403 | CAP2-406, CAP2-306, CAP2-107 | E2E 재현 조건 명확화 |
| CAP-FR-404 | CAP2-307 | 두 Gateway를 필수로 통일 |
| CAP-FR-405 | CAP2-501, CAP2-502, CAP2-503, CAP2-504, CAP2-505 | 평가 조건을 다섯 검수 단위로 분해 |

v1.0 본문/P1에서 추가로 명확화한 항목:

- 게시자 signing: CAP2-004로 필수 승격. 큰 provenance 플랫폼은 아님.
- bounded probe: CAP2-106. 기존 probe·출처 결합을 재사용.
- 최소 큐·DLQ·권한: CAP2-401/402로 필수 통일. 기업 운영 확장 아님.
- CI·재현·제출물: CAP2-405/406/407로 필수 목록에 포함.
- signed cache·appeal·receipt·고급 복구: P1 유지.
- (v2.1) CAP2-308 운영사 비신뢰 집행: v1.0에 대응 항목이 없는 신규 행이다. 1차 멘토링(2026-10) 반영으로 추가했으며 CAP-FR 번호를 새로 만들지 않는다.

기존 5,997줄 마스터의 `FR-*` 추적은 [전체 감사](MASTER_REQUIREMENTS_AUDIT_2026-09-19.md)의 원문 행·코드 근거를 이어 사용한다. CAP2와 원본 FR는 일대일이 아니다. 이 축소가 원본 전체 구현 완료를 뜻하지 않는다.

---

## 22. 개발 재개 시 사용할 기존 명령과 참고 자료

아래는 작성 시 저장소에 존재하는 명령이다. **이번 문서 작성 중 실행한 개발/배포 결과가 아니며**, 개발 재개 후 환경과 권한을 확인하고 사용한다.

```sh
# 저장소 루트 — 빠른 확인. 이것만으로 전체 RC 완료가 아니다.
npm ci
npm run build:backend
npm test
npm run build

# 기존 Docker/Compose 설정 검사
npm run stack:config

# 과거 원본 감사표의 집계 검사 — CAP2 완료율 계산기가 아님
node scripts/ops/check-master-audit.mjs

# (v2.1, 이번 변경) 운영사 비신뢰 장면 — 로컬 EVM·REPORT FIXTURE 스캐너 대역
npm run test:backend                  # consortium-scene.test.ts 포함(표본 5)
npm run evaluate:consortium-scene     # 기본 --samples 50 → benchmarks/results/consortium-scene-<sha7>-<timestamp>.json
                                      # 깨끗하지 않은 작업 트리는 거부(--allow-dirty는 결과에 기록하고 이름에 -dirty-<소스 해시 8자리>를 붙임), 조건 실패 시 미기록, 덮어쓰기 없음
```

native scoped-v2 테스트는 신뢰된 builder digest·Docker·선택 정책 등 사전 설정이 필요하다. 환경변수 하나만 켜고 준비가 끝났다고 가정하지 않는다. 정확한 명령·설정은 기존 workflow와 각 README를 따른다. 실제 체인 배포·모델 호출 명령은 키/비용/대상 확인 후 기존 스크립트를 사용한다.

### 내부 기준 자료

- [개발 인수인계](../DEVELOPMENT_HANDOFF.md) — 실행 방법과 기존 작업 역사.
- [원본 전체 감사](MASTER_REQUIREMENTS_AUDIT_2026-09-19.md) — 2026-09-19 상태·근거.
- [기존 전체 구현 계획](master-implementation-plan.md) — 장기 범위와 과거 진행 기록.
- [인터페이스](interface-contract.md), [운영 가이드](operations-runbook.md).
- [API](../apps/api/README.md), [Gateway](../apps/gateway/README.md), [Scanner](../services/scanner/README.md), [Resolver](../services/resolver/README.md).
- (v2.1) [v2.0 문서(보존)](MCPShield_캡스톤_최종_마스터문서_v2.0.md), [1차 멘토링 대응](mentoring-2026-10-response.md), [ADR-003](adr-003-validator-consortium.md) · [ADR-004](adr-004-blockchain-necessity-scene.md) · [ADR-005](adr-005-capstone-demo-path.md) · [ADR-006](adr-006-gateway-recheck-policy.md) · [ADR-007](adr-007-registry-owner-governance.md).

### 입력 문서 provenance

| 원문 | SHA-256 | 보존 원칙 |
|---|---|---|
| `MCPShield_전체_시스템디자인_해커톤_마스터문서.md` | `702268984174af450276b5292a4afccd6a4d5dce79738fe3abde41c4d30d4ea2` | 원본 5,997줄 및 전체 감사 보존 |
| `MCPShield_캡스톤용_전체_마스터팩_v1.0 (1).md` | `8b599a862d6a8a6f4ff781264cdd4f61ed16419652b8ddb94ac59f545c43a796` | 제공 원본 보존; 이 문서에서 범위 충돌 정리 |

외부 참고 자료는 2026-09-22 확인한 MCP 공식 보안 정책·Base 공식 chain ID 문서·동명 연구를 해당 본문에 연결했다. 학과의 공식 평가 기준이나 실제 계정 권한은 이 문서에서 확인됐다고 가정하지 않는다.

(v2.1) `postmark-mcp` 사건(2025-09), VirusTotal 기여형 정책(2016), Sigstore Rekor 투명성 로그는 1차 멘토링(2026-10)에서 비교 사례로 다룬 것으로 본문에는 이름만 적었다. 발표 자료에 넣을 때 원 출처를 확인해 링크를 단다.

## 마지막 결정

**MCPShield 캡스톤은 새로운 보안 플랫폼을 다시 만드는 프로젝트가 아니다. 이미 구현한 검사·검증·Gateway를 같은 릴리스 기준으로 연결하고, 정상 업무는 성공하며 위험한 업데이트는 실제로 차단된다는 증거를 완성하는 프로젝트다.**

(v2.1) 여기에 한 가지를 더한다. **운영사를 믿지 않는 회사도 체인을 직접(자기 API로) 확인해 폐기된 릴리스를 막을 수 있다는 것** — 이것이 이 프로젝트가 블록체인을 쓰는 이유이며, 그 장면을 측정과 함께 증명한다.

---

## 변경 기록

| 버전 | 날짜 | 내용 |
|---|---|---|
| v2.0 | 2026-09-22 | 캡스톤 범위·아키텍처·역할·완료 조건을 하나로 고정. P0 40개 검수 단위. 파일은 [그대로 보존](MCPShield_캡스톤_최종_마스터문서_v2.0.md) |
| v2.1 | 2026-10-11 | 1차 멘토링(2026-10) 반영. 검증 흐름/실행 통제 흐름 분리와 Gateway별 판정 조회 경로(§4.1), 본선 경로와 확장 구분(§2.4), 블록체인 필요 세 조건·컨소시엄·투명성 로그 비교(§9.1), owner 권한 운영(§9.5), CAP2-308 추가로 P0 41개, 실행 오버헤드 3측정(§12.5), 구현 순서 조정(§16), 발표 도입·영상·Q&A 보강(§18–19), Roadmap 추가(§20). 근거: ADR-003~007, [멘토링 대응 문서](mentoring-2026-10-response.md) |
