# MCPShield 캡스톤 최종 마스터 문서 v2.0

> **AI가 사용하는 외부 도구의 위험한 업데이트를 검사하고, 공동 판정을 실제 실행 차단으로 연결한다.**
>
> 개발 원칙: **이미 만든 것을 최대한 사용한다. 다시 만들지 않고, 끊어진 연결을 고치고, 실제로 동작한다는 증거를 완성한다.**

| 항목 | 기준 |
|---|---|
| 작성일 | 2026-09-22 |
| 문서 목적 | 캡스톤의 범위·아키텍처·역할·완료 조건을 하나로 고정 |
| 문서 성격 | 최종 개발·검수 기준. 구현 완료 보고서가 아님 |
| 코드 확인 기준 | `master/main`의 `9a251ae`; 기능 감사 기준은 `7bac78a` |
| 원본 보존 | 5,997줄 기존 마스터와 캡스톤 마스터팩 v1.0을 대체 삭제하지 않음 |
| 핵심 결정 | 제한된 Node MCP + Linux/Docker + 실제 LLM Agent + Base Sepolia + 두 Gateway |
| 개발 방법 | 기존 저장소·스키마·SDK·테스트·화면 재사용, 최소 수정·통합·실증 |
| 비목표 | 모든 MCP를 지원하는 상용 보안 플랫폼의 완성 |

**문서를 작성했다고 구현·배포·유료 API 사용·기존 목표의 자동 작업을 재개한 것은 아니다.** 후속 구현은 사용자와 합의한 작업 범위에서 진행한다. 이 문서는 첨부 문서의 명령을 실행한 기록이 아니라, 사용자가 요청한 범위 재설계 결과다.

## 읽는 순서

- 처음 이해할 때: §1 문제와 목표 → §2 범위 → §4 전체 흐름.
- 바로 개발할 때: §3 재사용 지도 → §5 필수 요구사항 → §16 실행 순서.
- 완료를 판단할 때: §12 평가 → §13 테스트 → §17 검수·증거.
- 발표 준비: §18 시연·발표 → §19 질문·한계.

---

## 0. 기존 문서와의 관계

### 0.1 무엇을 계승하고 무엇을 바꾸는가

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

### 0.2 우선순위의 단일 기준

- **P0:** §5의 40개 검수 단위. 각 행에 연결된 본문 조건과 증거까지 충족해야 완료다.
- **P1:** §2.3의 선택 기능. 없다고 P0 완료를 막지 않는다. 활성화했다면 안전성 회귀 검사는 필요하다.
- **Roadmap:** §20의 범위. 이번 캡스톤에서 신규 구현하지 않는다.
- 본문·시연·일정에서 우선순위를 임의로 다시 정하지 않는다. 변경할 때는 §5와 변경 기록을 함께 수정한다.
- 기존 `FR-*`, v1.0의 `CAP-FR-*`, 이 문서의 `CAP2-*`는 서로 다른 요구사항 체계다. §21에 매핑한다.
- 기존 70% 및 18.56%는 2026-09-19의 **다른 분모**에 대한 역사적 감사값이다. 이 문서의 완료율로 옮겨 쓰지 않는다.
- 40개는 **신규 기능 40개가 아니라 묶어서 검수할 40개 단위**다. 이미 존재하는 기능을 다시 만들라는 뜻이 아니다.

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

> 같은 테스트용 게시자가 서명한 정상·악성 MCP를 구분하고, 악성 릴리스의 합성 비밀값 유출 증거를 검증하여 Base Sepolia에 폐기를 기록한 뒤, 두 Gateway가 그 정확한 릴리스의 실행을 차단한다. 정상 릴리스는 실제 AI Agent가 계속 사용할 수 있다.

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
| 검증자 | 서로 다른 3개 키·프로세스. 조직적으로 독립된 기관이라는 주장 없음 |
| Gateway | 서로 다른 2개 프로세스와 분리된 상태/캐시. 같은 호스트여도 별도 프로세스로 표시 |
| 실제 AI | 하나의 실제 모델 기반 Agent. 기존 harness/SDK 연결 재사용을 우선 |
| 체인 | 로컬 EVM으로 회귀 검사, Base Sepolia로 공개 실증 |
| DB/큐 | 기존 SQL 저장소·작업 큐. 통합 실증은 PostgreSQL 한 인스턴스; 빠른 로컬 개발은 기존 SQLite 허용 |
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

### 3.4 재작성 방지 심사

새 코드 작성 전 PR에 다음 세 문장을 적는다.

- 기존 어느 모듈을 재사용하는가?
- 기존 모듈의 설정·연결·짧은 수정으로 해결되지 않는 이유는 무엇인가?
- 새 부분을 검증하는 가장 작은 재현 검사는 무엇인가?

코드량을 줄이기 위해 보안 검사를 삭제하지 않는다. 반대로 일반화·새 추상화·새 서비스를 캡스톤 완료 조건에 추가하지 않는다.

---

## 4. 전체 아키텍처와 Workflow

### 4.1 세 영역

```text
[검사: Control Plane]
등록 → Resolver → source/closure/runtime 고정
                    ├─ Static / version diff
                    ├─ 실제 AI 의미 분석 / 제한된 probe
                    └─ 격리 Sandbox / canary / synthetic sink
                                      ↓
                          Evidence + Policy 판정

[공동 상태: Trust Plane]
Validator A / B / C 각각 증거 확인 → EIP-712 → 2-of-3
                                      ↓
                            Base Sepolia Registry
                                      ↓
                          Indexer → DB projection/API

[실제 집행: Execution Plane]
실제 LLM Agent → MCP Client → Gateway A → 승인된 제한형 MCP
테스트 Client             → Gateway B → 같은 identity 검사
                              ↓
              REVOKED / 변조 / 불명확 / 만료 → 실행·전달 차단
```

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
7. A/B Gateway가 같은 폐기 identity를 거부한다. 후보 코드가 시작되지 않았음을 측정한다.

### 4.4 검사를 매 호출마다 다시 하지 않는다

무거운 분석은 새 source·실행 조건·정책 조합을 대상으로 한다. 실행 경로에서는 고정 identity와 유효한 최신 판정을 검사한다. 각 도구 호출에서는 기존 세션 승인·폐기·표면 검사를 재사용한다. **검사 1회가 영구 안전 인증을 뜻하지는 않는다.**

---

## 5. P0 요구사항 — 유일한 필수 검수 목록

다음 40개 행이 완료율의 분모다. 각 행의 하위 조건은 AND다. N/A로 분모를 조용히 줄이거나 부분 구현에 0.5점을 주지 않는다. 요구 변경 시 문서 버전과 매핑을 갱신한다.

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

### 5.4 Gateway·Agent — 7개

| ID | 필수 결과 | 완료 증거 | 담당 |
|---|---|---|---|
| CAP2-301 | 기존 MCP wrapper가 실제 client↔server 통신을 중계 | 선택 SDK/프로토콜의 정상 조회, framing·stderr 로그 검사 | F |
| CAP2-302 | 후보 실행 전에 exact bytes·승인·정책·기한을 확인 | 폐기/변조/불명확 릴리스의 후보 실행 start/spawn 0건과 양성 대조군 | F |
| CAP2-303 | 격리 시작 후 전체 tools/list 검증을 끝내기 전 tool 노출/호출을 차단 | runtime drift·pagination·미선언 tool 호출 거부, 세션 정리 검사 | F |
| CAP2-304 | 실행 중인 세션도 후속 호출에서 폐기·만료를 재검사 | 세션 유지 중 revoke 후 다음 tools/call 미전달; 검사/전달 경합 회귀 | F |
| CAP2-305 | strict 모드의 상태불명·stale·서명 오류는 허용하지 않음 | RPC/Indexer 장애·낡은 승인·잘못된 서명·명시적 거부의 fail-closed 검사 | F/B |
| CAP2-306 | 실제 LLM Agent 1종이 동일 Gateway를 통해 정상 도구를 사용 | 모델 선택→실제 tools/call→합성 결과 trace; SDK 스모크와 구분 | F/S |
| CAP2-307 | 두 독립 Gateway가 동일 release identity의 폐기를 집행 | A/B 프로세스·상태 저장소 구분, 같은 chain tx 이후 각 차단 시각과 이유 | F/B |

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
| CAP2-502 | Static / AI / Sandbox / Static+Sandbox / Full 5개 비교군 측정 | 동일 고정 표본·방법별 적용 가능성·stage 재사용 여부·TP/FP/FN/TN/보류 원자료 | S |
| CAP2-503 | 실제 Agent의 OFF/ON 결과와 정상 업무 성공률을 함께 측정 | 실제 sink/action oracle, 동일 시나리오, §12 반복·분모·실패 기록 | S/F |
| CAP2-504 | scan/admission/revoke 전파·chain 비용/시간을 실제 측정 | 환경·표본 수·시작/종료 정의·p50/p95·오류율·raw 결과 | B/S |
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

### 9.1 왜 체인을 사용하는가

한 회사 내부만 대상으로 하면 중앙 DB가 더 단순할 수 있다. 여기서는 검증자와 여러 Gateway가 같은 릴리스의 판정·폐기 이력을 공유하는 구조를 실증한다. 체인은 **검사가 옳았다는 사실을 자동 보장하지 않으며**, 서명된 판정과 상태의 공통 기록 역할을 한다.

### 9.2 검증자 검증 범위

3개 키를 한 함수에서 차례로 호출해 같은 verdict를 복사하는 것으로 완료하지 않는다. 각 프로세스는 기존 독립 검증 경로로 최소한 다음을 확인한다.

1. source/실행 identity·policy가 자신이 허용한 설정과 일치하는가.
2. evidence hash/root와 관찰·완결성·권한 근거가 유효한가.
3. 선언된 판정을 정책으로 도출할 수 있는가. 해당 프로필이 요구하는 재관찰을 수행했는가.
4. 서명 domain·chain·contract·validator set·nonce·deadline이 맞는가.

키와 실행 프로세스는 분리하지만 서로 다른 기관이나 서로 다른 탐지 엔진의 독립성까지 달성했다고 발표하지 않는다. 실제 키는 operator secret으로 주입하고 DB/browser/API 요청에 원문을 넣지 않는다.

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

테스트 파일이 존재한다는 이유만으로 PASS 처리하지 않는다. 실제 실행된 subtest와 조건부 SKIP을 확인한다.

### 13.2 네 종류의 검증을 분리

1. **빠른 로컬 검사:** 타입·unit·schema·replay. 개발 feedback용.
2. **Linux/Docker 필수 통합:** 실제 격리·준비·검증자·local chain·두 Gateway. secret 없이도 실행 가능한 회귀 검사.
3. **승인된 실환경 검증:** 실제 모델과 Base Sepolia. 비용/키가 있어야 하며 fork PR에 secret을 제공하지 않음.
4. **브라우저·발표 검수:** 실제 화면 조작·링크·PPT/PDF·영상·clean 환경 재현.

CI의 합성 모델 응답은 provider 계약 검사이지 실제 모델 품질 증거가 아니다. 테스트넷/실제 모델을 모든 PR에서 반복 호출할 필요는 없다. 승인된 release 검증으로 분리하되 **같은 RC 코드·정책·이미지·dataset**의 증거를 연결한다.

### 13.3 RC 통과 조건

- §5 P0 40개가 각각 증거와 연결되어 완료 판정됨.
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

**현재 CAP2 완료율: 미산정.** 기존 기능을 위 40개에 매핑한 후 실제 증거를 확인해야 한다. 문서만 새로 썼다고 완료율을 올리지 않는다.

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

| 단계 | 할 일 | 기존 자산 | 종료 조건 |
|---|---|---|---|
| A. 범위/환경 고정 | CAP2 매핑·Node 프로필·실행 버전·키/비용·Linux 환경 확인 | 감사·handoff·기존 설정 | 미지원/외부 의존 목록과 재사용 경로 확정 |
| B. 핵심 실패 수정 | scoped-v2 증거/권한/설정 원인 추적, 필요한 기존 guard 수정 | scanner/API/validator native 테스트 | 실제 malicious FAIL과 safe PASS, Linux 통합 성공 |
| C. 병렬 보완 | S: 게시자 서명·holdout; B: testnet; F: Agent·기존 UI 연결 | fixture/배포 스크립트/harness/components | 모듈별 실제 증거 확보 |
| D. 하나의 흐름으로 통합 | source→scan→quorum→testnet→A/B 차단 및 safe 업무 | prepared fullcycle | 같은 identity/정책/RC의 end-to-end 기록 |
| E. 측정·재현 | 5비교군·실제 Agent·latency·전파·clean 환경 | 기존 benchmarks/CI | 원자료·한계 포함 평가 보고 |
| F. 동결·발표 | P0 검수, 10회 local 데모, PPT/PDF·영상·링크 | 기존 pitch/guide | §13 RC 조건과 §17 증거 목록 완결 |

B가 막혀도 C의 문서·데이터 라벨·비밀 없는 설정 준비는 병렬 진행할 수 있다. 반대로 잘못된 통합 판정 위에서 평가 숫자나 영상을 확정하지 않는다.

### 16.1 새로 만드는 부분의 상한

원칙적으로 새 작업은 **게시자 서명 fixture/검사, 부족한 평가 표본·결과 묶음, 기존 Agent harness의 Gateway 연결, 제출용 최종 산출물**에 집중한다. 나머지는 기존 함수·설정·테스트의 수정이다. 이 밖의 새 서비스/프레임워크가 필요하다고 판단되면 범위 변경으로 검토한다.

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
엄격 완료율 = 완료 CAP2 수 / 40 × 100
착수 범위 = (완료 + 부분) / 40 × 100
```

이는 요구 충족률이지 코드량·남은 작업 시간의 비율이 아니다. 각 행의 크기가 다르므로 일정 추정에는 그대로 사용하지 않는다.

### 17.2 최종 evidence bundle

다음은 **앞으로 만들어 채울 산출물 목록**이며 현재 존재/완료 선언이 아니다. 기존 유효한 로그·결과는 재사용하고 SHA·환경 차이를 적는다.

| 산출물 | 최소 내용 |
|---|---|
| RC manifest | 코드 SHA, 의존성 lock hash, 이미지, 정책, dataset, 모델, chain/contract |
| CAP2 ledger | 40개 완료/부분/미완료와 근거 링크 |
| CI/native 결과 | 필수 step/subtest, PASS/FAIL/SKIP, 10회 local 반복 결과 |
| Publisher 증거 | safe/bad 서명 검증과 변조·다른 키 거부 |
| Trust 증거 | 검증자별 확인/서명, 실제 tx/event 및 projection |
| Gateway/Agent 증거 | safe 실제 도구 호출, A/B 후보 start 0건, drift/후속 차단 |
| 평가 묶음 | 표본 manifest·raw 결과·5비교군·ASR/정상 업무·latency·비용 |
| 재현 문서 | 필요한 권한·버전·정확한 명령·예상 결과·정리/복구 |
| 발표 묶음 | 열리는 PPTX/PDF, 3분 영상, GitHub/Explorer 링크, 한계/출처 |

이미지·영상만으로 수치나 내부 차단을 증명하지 않는다. 로그/trace/manifest와 연결한다. 재현에 필요한 synthetic fixture는 제공하되 실제 공격 인프라나 민감 payload를 포함하지 않는다.

---

## 18. 시연과 발표

### 18.1 3분 영상 기본안

| 시간 | 보여줄 것 | 핵심 메시지 |
|---|---|---|
| 0:00–0:20 | AI의 합성 메일 조회 성공 | 정상 업무는 계속 된다 |
| 0:20–0:45 | 같은 게시자가 서명한 악성 업데이트, 격리 OFF 실험 | 정상 서명만으로 행동 안전을 알 수 없다 |
| 0:45–1:20 | Static/AI/Sandbox evidence | 검사 근거가 있다 |
| 1:20–1:50 | 독립 검증자·2-of-3·실제 테스트넷 tx | 판정을 공동 상태로 기록한다 |
| 1:50–2:20 | Gateway A/B 차단, 후보 start 0건 | 기록이 실제 실행 권한으로 이어진다 |
| 2:20–2:45 | 비교 평가·정상 작업 성공률·지연 | 효과와 비용을 측정했다 |
| 2:45–3:00 | 지원 범위·한계·결론 | 모든 MCP 안전 인증은 아니다 |

3분은 편집 영상 길이다. 수분 걸리는 scan과 거래 확인을 3분 내 실시간 완료한다고 약속하지 않는다. 컷 편집·사전 실행·녹화·REPLAY는 표시하고 원본 trace/tx에 연결한다.

### 18.2 발표자료 기본 10장

1. 문제: 정상 업무처럼 보이는 위험한 도구 업데이트.
2. 보호 대상·지원 범위: 합성 메일 조회, Linux/Node 프로필.
3. 해결 흐름: 검사 → 공동 판정 → 실제 차단.
4. 기존 구현 재사용 아키텍처와 기술 선택.
5. AI의 역할과 no-AI 기준선 비교.
6. 블록체인의 역할과 중앙 DB 대비 선택 이유.
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
| 결국 package scanner 아닌가? | 탐지뿐 아니라 exact runtime 승인·폐기 상태와 실제 Agent 실행 권한을 연결한다 |
| DB로 충분하지 않나? | 단일 조직은 가능하다. 여러 검증자/소비자의 공유 판정 이력을 실증하기 위해 체인을 선택했다 |
| 블록체인이 안전성을 보장하나? | 아니다. 증거 검증이 잘못되면 잘못된 판정이 기록될 수 있다 |
| AI가 없어도 되는가? | Static+Sandbox와 Full을 비교해 기여를 측정한다. 개선이 없으면 그 결과도 공개한다 |
| 정상 도구도 막히지 않나? | 보류와 악성 판정을 구분하고 정상 업무 성공률·차단률을 함께 제시한다 |
| 세 키가 모두 같은 팀 소유 아닌가? | 맞다. quorum 프로토콜 실증이며 다기관 탈중앙 운영 완성은 아니다 |
| runtime drift가 모든 악성 행동을 잡나? | 아니다. 도구 표면 변경을 탐지하며 표면이 같은 내부 악성 행동은 놓칠 수 있다 |
| 이미 실행 중인데 폐기되면? | 후속 호출을 다시 검사한다. 이미 발생한 유출 복구·idle process 즉시 종료를 보장하지 않는다 |
| Gateway를 우회하면? | 보호 경계 밖이다. endpoint 강제 관리·기업 배포 통제는 Roadmap이다 |
| 실제 메일/CRM에 바로 쓰나? | 아니다. 이 캡스톤은 합성 데이터와 제한된 실행 프로필의 실증이다 |
| Sandbox escape/time bomb은? | 완전 방어를 주장하지 않는다. 최소 권한·격리·시간 제한과 지원 범위를 공개한다 |
| 정상 서명은 npm 공식 인증인가? | synthetic 테스트 게시자 서명이다. npm provenance와 구분한다 |
| 성능이 기대보다 낮으면? | 기능을 숨기지 않고 실측과 실패 원인·한계를 보고한다. 일반 안전성을 과장하지 않는다 |

사용 금지 표현: “모든 MCP 안전 인증”, “100% 악성코드 탐지”, “완전 탈중앙화”, “AI가 안전을 확정”, “준비 상태 READY이므로 실행 허용”.

권장 표현: **“정해진 정책과 시험 환경에서 위험 증거를 확인하고, 미검증·변조·폐기된 릴리스의 실행을 Gateway 경로에서 제한한다.”**

프로젝트 이름과 동일한 `MCPShield` 연구가 이미 존재한다. 제출 시 부제 **“Release Firewall: 검증된 릴리스만 실행하는 MCP 보안 Gateway”**를 붙이고 선행연구와 구분한다. 동일 명칭이나 기능 최초성을 근거 없이 주장하지 않는다. [동명 연구](https://arxiv.org/abs/2602.14281)

---

## 20. 장기 Roadmap — 캡스톤 분모에서 제외

1. **지원 확대:** PyPI·다른 언어·macOS/Windows enforcement·private registry·원격 서버 assurance.
2. **격리 강화:** gVisor/microVM/WASI·TEE·강한 syscall 관찰·secret broker.
3. **공급망 연계:** Sigstore/SLSA·registry/IDE 통합·표준화된 assurance 표시.
4. **분산 신뢰:** 독립기관 validator·운영 거버넌스·HSM/KMS·멀티체인.
5. **기업 운영:** stage별 큐·autoscaling·replica/sharding·multi-region·PITR·장기 SLO·실제 알림 운영.

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
```

native scoped-v2 테스트는 신뢰된 builder digest·Docker·선택 정책 등 사전 설정이 필요하다. 환경변수 하나만 켜고 준비가 끝났다고 가정하지 않는다. 정확한 명령·설정은 기존 workflow와 각 README를 따른다. 실제 체인 배포·모델 호출 명령은 키/비용/대상 확인 후 기존 스크립트를 사용한다.

### 내부 기준 자료

- [개발 인수인계](../DEVELOPMENT_HANDOFF.md) — 실행 방법과 기존 작업 역사.
- [원본 전체 감사](MASTER_REQUIREMENTS_AUDIT_2026-09-19.md) — 2026-09-19 상태·근거.
- [기존 전체 구현 계획](master-implementation-plan.md) — 장기 범위와 과거 진행 기록.
- [인터페이스](interface-contract.md), [운영 가이드](operations-runbook.md).
- [API](../apps/api/README.md), [Gateway](../apps/gateway/README.md), [Scanner](../services/scanner/README.md), [Resolver](../services/resolver/README.md).

### 입력 문서 provenance

| 원문 | SHA-256 | 보존 원칙 |
|---|---|---|
| `MCPShield_전체_시스템디자인_해커톤_마스터문서.md` | `702268984174af450276b5292a4afccd6a4d5dce79738fe3abde41c4d30d4ea2` | 원본 5,997줄 및 전체 감사 보존 |
| `MCPShield_캡스톤용_전체_마스터팩_v1.0 (1).md` | `8b599a862d6a8a6f4ff781264cdd4f61ed16419652b8ddb94ac59f545c43a796` | 제공 원본 보존; 이 문서에서 범위 충돌 정리 |

외부 참고 자료는 2026-09-22 확인한 MCP 공식 보안 정책·Base 공식 chain ID 문서·동명 연구를 해당 본문에 연결했다. 학과의 공식 평가 기준이나 실제 계정 권한은 이 문서에서 확인됐다고 가정하지 않는다.

## 마지막 결정

**MCPShield 캡스톤은 새로운 보안 플랫폼을 다시 만드는 프로젝트가 아니다. 이미 구현한 검사·검증·Gateway를 같은 릴리스 기준으로 연결하고, 정상 업무는 성공하며 위험한 업데이트는 실제로 차단된다는 증거를 완성하는 프로젝트다.**
