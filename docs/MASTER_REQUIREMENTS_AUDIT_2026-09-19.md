# MCPShield 마스터 문서 전체 요구사항 재감사

감사일: 2026-09-19 KST. **전체 완료 아님. 신규 구현 중단 후 감사 체크포인트.**

## 0. 결론 — 핵심 기능 70%, 문서 전체 검수 완료 18.56%

**핵심 흐름은 작동하지만, 마스터 문서 전체에 적힌 제품·운영·확장·제출 조건까지 완성된 것은 아니다.**
기존에 말한 ‘전체 약 70%’는 산식 없는 개발 진척 추정이었다. 이번 70%는 아래 **FR 50개만의
검증 완료율**이다. 서로 같은 지표로 취급하지 않는다.

| 집계 범위 | 전체 | 완료 | 부분 | 미완료 | 엄격 완료율 |
|---|---:|---:|---:|---:|---:|
| 명시된 핵심 FR | 50 | 35 | 15 | 0 | 70.00% |
| FR 밖의 추가 검수 조건 | 214 | 14 | 106 | 94 | 6.54% |
| **문서 전체의 중복 제거 검수 항목** | **264** | **49** | **121** | **94** | **18.56%** |

- 전체 산식: **49 ÷ 264 × 100 = 18.560606…%**. 표시값은 소수 둘째 자리 반올림.
- 부분 121개를 포함한 **착수 범위**는 **170 ÷ 264 = 64.39%**. 완료율이 아니다.
- 이 264개는 원문을 이번 감사 기준으로 분해·통합한 **검수 단위 수**다. 원문에 ‘총 264개’라고
  쓰여 있다는 뜻은 아니다. 각 행의 분모·상태·근거를 아래 공개해 재산정할 수 있게 했다.
- 큰 Production 확장과 작은 검수 조건도 각 1건이다. **개발 공수/코드량의 18.56%만 끝났다는
  의미가 아니며**, 항목 분류 방식과 운영 증거 기준에 의존하는 문서 충족률이다.
- 추가 조건 표는 이미 핵심 FR에서 센 기능을 뺀 잔여 범위다. 예를 들어 Backend 추가표의
  낮은 비율을 ‘백엔드 구현이 5%뿐’이라고 읽으면 안 된다.

### 핵심 FR만 영역별로 보면

| 영역 | 완료 / 부분 / 미완료 | 완료율 | 대표 남은 조건 |
|---|---|---:|---|
| 수집·식별 8개 | 4 / 4 / 0 | 50.00% | publisher 근거, JCS 구현 방식, 프로필 전반의 재사용/baseline |
| Security·AI 13개 | 8 / 5 / 0 | 61.54% | 일반 언어 분석, DNS/OCI 파일 관찰, 새 scoped native probe 실패 |
| 정책·Blockchain 12개 | 10 / 2 / 0 | 83.33% | 자동 만료/상태 전달, validator 거버넌스 운영 |
| Gateway 10개 | 8 / 2 / 0 | 80.00% | 지원 runtime 경계와 운영 runner, push·idle 세션 폐기 처리 |
| 운영·감사 7개 | 5 / 2 / 0 | 71.43% | 전체 UI 수용 검사, chain retry 상한/DLQ |

### 다음 개발자가 먼저 확인할 것

1. **새 Node scoped-v2 native 실패 2건**: 실제 결과가 `ABSTAIN`, 기대는 `FAIL`이다.
   안전하게 승인하지 않은 상태지만 악성 증거→폐기 시나리오가 완성되지 않았다. 원인 수정과 재검증 필요.
2. **publisher 서명 데모 없음**: 검증자 EIP-712 서명과 게시자의 패키지 서명은 다르다.
   MOCK/replay `VALID` 고정 표시를 실제 publisher 검증으로 주장하지 말 것.
3. **실제 환경 검증**: 외부 AI의 독립 라벨/FPR/ASR, Base Sepolia, 실제 S3/KMS·기관별 키 운영,
   최신 전체 공개 배포는 남아 있다. 공개 Railway는 기존 합성 데모다.
4. **운영 안전성**: chain 재시도 상한·circuit breaker, job-scoped credential,
   9종 운영 알림/실제 수신, PITR·키 복구·RPO/RTO 증거가 필요하다.
5. **지원 기능 확대**: behavior manifest 전체, remote assurance, action별 사용자 확인/secret broker,
   자동 drift 재검사, PyPI/OS adapter/강한 격리 등은 부분 또는 미구현이다.
6. **제출물**: HTML 외 실제 PPT/PDF·영상·리허설, LICENSE/notices·신고 채널·QR/링크 점검이 남는다.

재계산 명령(저장소 루트): `node scripts/ops/check-master-audit.mjs`.
선택적으로 원문 경로를 첫 인자로 주면 원문 SHA-256 및 5,997줄도 검증한다.
이 검사는 ID 중복·누락·표 구조·상태·산술을 확인하며, 사람의 상태 판정 자체를 증명하지 않는다.

## 1. 기준과 읽는 법

사용자 요청에 따라 계정 주간 잔여 사용량 **50%**가 확인된 시점에 신규 구현을 중단했다.
이후에는 진행 중인 체크포인트 보존·검증 결과 확인·이 문서 작성만 수행했다.
감사와 현재 작업 마감에도 사용량이 들기 때문에 50%는 최종 잔여량 보장값이 아니라 중단 기준이다.
신규 구현 중단 확인 당시 usedPercent=50, 감사 마감 직전 조회는 usedPercent=55(45% 잔여)였다.
이는 계정 공유 주간 한도이며 이 작업만의 사용량 계측은 아니다.

- 원문: `MCPShield_전체_시스템디자인_해커톤_마스터문서.md`
- 원문 SHA-256: `702268984174af450276b5292a4afccd6a4d5dce79738fe3abde41c4d30d4ea2`
- UTF-8 원문: 227,167 bytes, **5,997줄** (`split(/\r?\n/)`, 마지막 빈 줄 포함).
- 통합 코드 기준: `7bac78a689b478e2aa6f4e2714a425d5c17a263b`, `master/main`.
- 별도 보존: Security `8c13b9c` OCI scoped-v2 scanner checkpoint. **미통합·native 미검증**이며 통합 완료율을 올리는 데 사용하지 않는다.
- 원본 `mcp/main`과 기존 Railway 데모는 보존. 이 감사는 최신 버전 공개 배포 완료 선언이 아니다.

### 판정 규칙

| 상태 | 의미 |
|---|---|
| 완료 | 해당 요구의 구현과 재현 가능한 수용 증거가 모두 있음. 지원 범위는 근거 열에 제한해 명시. |
| 부분 | 일부 구현/시험은 있으나 요구의 나머지 조건, 통합, 실제 실행 또는 필요한 운영 증거가 없음. 실패·SKIP도 여기 포함. |
| 미완료 | 해당 기능/산출물/달성 결과의 구현·검증 증거를 확인하지 못함. 계획만 있는 경우 포함. |

`완료`는 제품 전체의 무결함·상용화·모든 MCP 지원을 뜻하지 않는다. 계약 HTTP 테스트는
API 계약의 근거로 사용할 수 있지만 실제 외부 모델 품질·비용의 증거는 아니다. 로컬 EVM은
컨트랙트 동작 근거이나 Base Sepolia 배포 증거가 아니다. 테스트 수는 요구사항 수가 아니다.

**엄격 완료율 = 완료 요구사항 수 ÷ 중복 제거한 전체 요구사항 수 × 100.**
부분 구현에 임의로 0.5점을 주지 않는다. 별도로 `(완료+부분)/전체`를 표시할 경우 이름은
‘구현 착수 범위’이며 완료율이 아니다. 작업 시간·코드량·향후 자동 작업은 분자에 넣지 않는다.
이 수치는 아래 감사표의 분류/분모에 대한 정확한 산술값이지, 남은 개발 공수의 정밀 예측이 아니다.

## 2. 전체 원문 범위 확인

| 원문 행 범위 | 검토 범위 | 근거 문서/집계 처리 |
|---|---|---|
| 1–964 | 제안서·50 FR·NFR·위협 모델·지원 단계·규모 | [Main](audit/2026-09-19/main.md). FR 50개 + 독립 NFR/확장 요구. |
| 965–1711 | API·데이터 모델·전체 아키텍처 | [Backend](audit/2026-09-19/backend.md). FR 반복 제외, 추가 동작 집계. |
| 1712–2090 | 분석 엔진 | [Security](audit/2026-09-19/security-ai.md). FR 반복 제외, 추가 분석·안전 조건 집계. |
| 2091–2485 | 블록체인·검증자 | Backend. FR 및 추가 trust/운영 조건 연결. |
| 2486–2824 | Gateway | [Frontend/Gateway/Ops](audit/2026-09-19/frontend-gateway-ops.md). FR 및 추가 실행 통제 연결. |
| 2825–3428 | 병목·확장·장애·복구 | Backend. 규모 가정과 실제 기능/복구 목표 구분. |
| 3429–3637 | 관측성 | Frontend/Gateway/Ops. metric·dashboard·alert 수용 조건. |
| 3638–3775 | trade-off | Main. 기존 기능 반복은 매핑, 후속 OPA/격리 tier는 별도. |
| 3776–4793 | 개발·CI/CD·데모·일정·역할 | Frontend/Gateway/Ops. 기능·시험·제출 산출물과 일정 예시 구분. |
| 4794–4990 | 벤치마크·재현성 | Security. 실제 모델·데이터셋·분포 측정과 fixture 계약 구분. |
| 4991–5345 | 최종 제안서·효과·도입 | Frontend/Gateway/Ops. 앞선 기능 반복 제외. |
| 5346–5431 | 위험·윤리·한계 | Security. 범위 제한/실제 보호 기능에 연결. |
| 5432–5555 | Q&A | Frontend/Gateway/Ops. 답변 문구를 별도 기능으로 부풀리지 않음. |
| 5556–5689 | 레퍼런스 | Main. 출처 목록은 기능 분모 제외, 제출 검수에 연결. |
| 5690–5817 | 부록 A 수용 테스트 | Security. 기존 요구의 증거 조건에 연결; 독립 추가 동작만 별도. |
| 5818–5877 | 부록 B 배포·발표 체크리스트 | Frontend/Gateway/Ops. 산출물/운영 검수 포함. |
| 5878–5997 | ADR·용어·최종 요약 | Main. 기존 요구로 매핑; 용어/빈 줄은 분모 제외. |

전체 5,997줄을 읽되 **줄 수를 기능 개수로 세지 않는다.** 같은 기능이 FR·아키텍처·
데모·수용 테스트에 반복되면 한 번만 센다. 원문의 5천만 요청/일, 사용자 수, 수익 추정은
설계 가정이며 이미 확보해야 하는 고객/매출 요구가 아니다. 선택 대안은 기능 중심으로
평가하며 Nginx·Redis·Kafka·RabbitMQ를 각각 무조건 설치해야 완료인 것으로 해석하지 않는다.
명시된 Pilot/Production 확장은 전체 범위에 포함한다. 새 marketplace·토큰/DAO·모든 remote
서버 내부 코드 증명 등 명시적 비목표는 추가하지 않는다.

## 3. 명시된 FR 50개

이 표는 원문 FR 한 개를 한 항목으로 유지한다. 요구 안의 조건 하나라도 남으면 `부분`이다.
추가 표는 FR의 동일 조건·시험을 다시 세지 않는다. 코드 경로는 저장소 루트 기준이다.

| ID | 원문 행 | 요구사항 | 상태 | 구현·검증 근거 / 남은 조건 |
|---|---|---|---|---|
| FR-001 | 506 | npm spec·tarball·OCI digest 지원 입력 | 완료 | `services/resolver/src/resolver.mjs`, `oci.mjs`; master-scanner/oci-resolver/acquisition/API tests. 공개 허용 registry·bounded artifact 범위, 임의 URL proxy 아님. |
| FR-002 | 507 | mutable tag를 exact version/digest로 고정 | 완료 | resolver와 OCI manifest 검증, 태그 변경/identity 회귀. mutable tag를 승인 identity로 사용하지 않음. |
| FR-003 | 508 | registry·namespace·publisher·retrieval provenance 저장 | 부분 | 원본 URL/name/version/retrievedAt와 선언된 maintainer 기록. publisher는 verified:false이며 OCI publisherEvidence는 비어 있음. 신원 증명 입력은 남음. |
| FR-004 | 509 | artifact SHA-256 및 bytes32 | 완료 | resolver·`packages/contracts-sdk/src/v2-identity.mjs`, golden identity/변조 테스트. |
| FR-005 | 510 | JCS에 준하는 manifest canonical hash | 부분 | `canonical-json.mjs`; UTF-16 key order, 유한 수, lone surrogate 거부, Unicode/key order 회귀. 원문 3798·4051–4075의 ‘검증된 JCS library, 직접 구현 금지’는 미충족(직접 serializer). |
| FR-006 | 511 | 전체 tools/list의 결정적 surface hash | 완료 | `tool-surface.mjs`, `protocol-guard.mjs`; 전체 pagination/중복/cursor/drift 테스트. |
| FR-007 | 512 | 유효 artifact+policy 중복 deep scan 회피 | 부분 | `control-store.ts`; `control-plane.test.ts` FR-007/008 실제 SQLite/PostgreSQL·alias key·quota 검사. 단 같은 tenant/release/policy 범위이며 source/다른 release 공용 artifact 재사용은 미완료. |
| FR-008 | 513 | VERIFIED 자동 baseline + 명시적 baseline | 부분 | 같은 intake tests에서 이전 VERIFIED 선택 및 사용자 기준선 검사. 버전 diff 사용 경로에 적용. prepared Node/OCI baseline은 미지원·명시 거부하므로 전체 지원 범위는 부분. |
| FR-101 | 519 | 메타데이터 지시·민감 경로·전송·Unicode 탐지 | 완료 | `semantic.mjs`, `analysis.mjs`, metadata corpus/scanner tests. 알려진 규칙 탐지이며 일반 recall 목표 달성은 별도. |
| FR-102 | 520 | name/description/schema/annotation diff | 완료 | `analysis.mjs`; master-scanner semantic diff 회귀. |
| FR-103 | 521 | install/child/shell/network/filesystem 정적 분석 | 부분 | `scanner.mjs`, `packages/artifact-policy/import-policy.mjs`; AST/위험 호출 synthetic tests. 완전한 interprocedural dataflow 증명은 별도. 일반 shell/Python·난독 payload·keychain 분석은 부족. |
| FR-104 | 522 | SBOM 및 의존성/버전/install script 변화 | 완료 | npm closure·CycloneDX와 OCI native Trivy/SBOM 검사, dependency/install diff tests. |
| FR-105 | 523 | 후보 텍스트를 데이터로 분리·JSON 출력 강제 | 완료 | `semantic.mjs`, `ai-transport.mjs`, scoped-semantic actual loopback HTTP/prompt robustness tests. 실제 외부 모델 품질을 뜻하지 않음. |
| FR-106 | 524 | 위험 유형·근거 span·confidence·권장 테스트 | 완료 | structured schema·host-computed citation·invalid claim 거부, AI provider/semantic tests. |
| FR-107 | 525 | 미검증 artifact는 일회성 격리에서만 실행 | 완료 | Linux Docker scanner/import/lock 분리·native host canary 테스트. legacy fixture path는 검토된 합성 전용, 임의 artifact 승인 통로 아님. |
| FR-108 | 526 | readonly/tmpfs/CPU/RAM/PID/time 제한 | 완료 | `sandbox.mjs`, prepared/OCI 런타임과 실제 Docker isolation/resource tests. kernel escape 완전 방어 보증 아님. |
| FR-109 | 527 | 외부 기본 거부·제한된 egress proxy | 부분 | network-none/internal network+synthetic allowlist proxy 및 직접 외부 연결 차단 native tests. 실제 고객 endpoint 허용 기능은 별도. 완전한 DNS/TCP/TLS 관찰·테스트별 일반 egress 정책은 미완료. |
| FR-110 | 528 | 다종 dummy canary와 접근·전송 관찰 | 부분 | env/SSH/cloud/browser/wallet 등 합성 canary와 sink의 hash 연결, sandbox/proxy tests. OCI 파일-read syscall 및 DNS-label 유출 관찰은 미완료. |
| FR-111 | 529 | AI 생성 정상/공격 호출을 synthetic target에 실행 | 부분 | schema 강제 probe 생성·계약 HTTP·합성 대상 실행 경로 있음. 최신 scoped Node native probe gate 실패, 실제 외부 모델 생성 평가 미실행. |
| FR-112 | 530 | file/network/process/MCP를 하나의 scan trace로 연결 | 부분 | scan trace·Node observer·MCP/sink 이벤트 연결 있음. non-Node OCI의 완전한 filesystem/syscall 관찰은 없음. |
| FR-113 | 531 | AI-only 경고로 영구 폐기 금지 | 완료 | prepared/OCI/control policy가 결정론적 근거 없는 FAIL과 불완전 검토를 ABSTAIN으로 처리; 정책 테스트. |
| FR-201 | 537 | 모든 판정의 versioned policyHash | 완료 | policy registry·V2 binding·immutable policy tests. scoped-v2는 v1과 별도 identity. |
| FR-202 | 538 | root/digest/status/validity/validator만 온체인 | 완료 | `ReleaseRegistryV2.sol`, `v2.ts`, EVM typed-data/storage tests. 원문 보고서는 오프체인. |
| FR-203 | 539 | EIP-712 validator 서명 | 완료 | SDK·독립 single-key CLI·실제 local EVM recovery tests. |
| FR-204 | 540 | chain/contract/release/policy/root/verdict/deadline/nonce binding | 완료 | V2 domain 재구성·서명 replay/다른 domain·nonce·validator set 거부 테스트. |
| FR-205 | 541 | 동일 validator 중복 집계 방지 | 완료 | Solidity unique vote/nonce 및 중복 signature tests. |
| FR-206 | 542 | 일반 승인/최종 폐기의 2-of-3 | 완료 | 실제 local EVM quorum·반대 투표 순서·safe/revoked 두 Gateway end-to-end. 독립 기관 운영은 별도. |
| FR-207 | 543 | 결정론적 critical 1인 격리 ≤24시간 | 완료 | signed quarantine/reason allowlist/TTL·만료 후 자동 재승인 금지 EVM tests. |
| FR-208 | 544 | REVOKED terminal, 수정 digest는 새 release | 완료 | policy를 바꿔도 전역 revoked 유지, 새 exact identity와 state invariant tests. |
| FR-209 | 545 | chain의 문자열·보고서·PII·비밀 저장 금지 | 완료 | V2 ABI/struct는 digest·정수·주소, 원문 저장 필드 없음. |
| FR-210 | 546 | 상태 변경 event와 indexer 소비 | 부분 | registry event·cursor/reconcile 및 EVM event tests. 시간 경과로 조회되는 만료는 명시 처리 시 event 확정. 자동 expiry transaction 및 Gateway push 소비는 미완료. |
| FR-211 | 547 | validator 변경의 multisig 또는 지연 역할 변경 | 부분 | 추가/교체는 1일 timelock. `disable`은 owner EOA 즉시 실행 가능, 실제 multisig/운영 거버넌스 미검증. |
| FR-212 | 548 | non-upgradeable 고정 contract 배포 | 완료 | 고정 Solidity·immutable 주소·nonproxy deploy-v2 스크립트/local EVM 배포. 외부 테스트넷 배포는 추가 요구. |
| FR-301 | 554 | client config를 Gateway command로 래핑 | 완료 | `apps/gateway/README.md` stdio config와 actual SDK client→Gateway→child tests. |
| FR-302 | 555 | spawn 전 로컬 exact bytes·최신 허용 상태 확인 | 완료 | prepared/OCI 로컬 image/CID/closure/config 확인, pre-create/pre-start admission 및 block-before-spawn tests. |
| FR-303 | 556 | 미검증 runtime의 host 직접 실행 금지 | 부분 | 지원 npm/OCI는 제한 Docker, public input으로 command/path override 불가. native isolation tests. 제한 Docker 경로는 검증했으나 host fixture runner·운영 Linux runner/지원 프로필 차이를 남김. |
| FR-304 | 557 | runtime surface 불일치 시 client 노출 차단 | 완료 | 전체 tools/list 검증 전 suppression, pagination/drift·list_changed tests. |
| FR-305 | 558 | VERIFIED·validity·policy·digest 모두 만족해야 ALLOW | 완료 | signed-admission·V2 chain-reader와 decision table/freshness/batch final-fence tests. |
| FR-306 | 559 | strict fail-closed / balanced signed cache | 완료 | signature·tenant·operation·TTL·known revocation 거부, RPC 장애/조직 indexer fallback tests. |
| FR-307 | 560 | 폐기 event 후 신규·실행 중 후속 호출 차단 | 부분 | 두 실행 중 Gateway의 다음 tools/call 재검사와 폐기 journal 검증. push event 기반 idle 세션 즉시 중단/전파 SLA는 미완성. |
| FR-308 | 561 | 차단 사유·release·상태·보고서 링크, 비밀 비노출 | 완료 | Gateway decision/CLI 구조화 오류, 서버 stderr 비노출, UI의 신뢰된 한국어 고정 안내 테스트. |
| FR-309 | 562 | stdio framing/stdout protocol-only | 완료 | protocol guard·stdio SDK·batch/EOF/오류·stdout 비오염 회귀. |
| FR-310 | 563 | stateless와 legacy initialize 클라이언트 구분 | 완료 | protocol guard matrix·actual SDK 및 release image의 양쪽 HTTP MCP era smoke. |
| FR-401 | 569 | scan→validator→chain→admission trace | 완료 | `packages/telemetry/index.mjs`, `fullcycle-telemetry.test.ts`; 실제 local EVM+HTTP exporter의 공통 trace/parent 검증. 운영 collector 전개는 별도. |
| FR-402 | 570 | 상태·투표·root·tx·만료 검색 UI | 부분 | `/console`와 BFF/API integration·built native POST 검증. 실제 브라우저 hydration/상호작용 전체 수용 검사는 미완료. |
| FR-403 | 571 | 원문 evidence RBAC·접근 감사 | 완료 | reader403·tenant 경계·AES-GCM·evidence.accessed event, 실제 API tests. |
| FR-404 | 572 | retryable/영구 실패·DLQ 재처리 | 부분 | SQL lease/attempt fencing·backoff·최대시도·DLQ retry quota·WORKER_LOST tests. chain outbox의 비종결 장애에는 재시도 상한/backoff/DLQ가 부족하며 단계별 DLQ도 미구현. |
| FR-405 | 573 | scan/chain action 멱등성 | 완료 | request key+digest, 원자적 queue/audit, signed raw transaction outbox·crash/reorg/retry tests. |
| FR-406 | 574 | 오탐 신고·재검증을 release history에 연결 | 완료 | API/BFF appeal→같은 tool의 새 digest/정책 검사→종료/실패 history, PostgreSQL concurrency 및 응답 유실/같은 key tests. |
| FR-407 | 575 | 선택적 action receipt batch Merkle anchor | 완료 | local SQLite hash chain→encrypted batch→ReceiptAnchorRegistry·durable outbox, local EVM N-confirmation/reorg tests. 외부 배포는 별도. |

## 4. FR 밖의 독립 요구사항

아래 EX 항목은 50 FR에 포함되지 않은 추가 검수 단위다. ‘단위’는 하나의 기능·운영 목표·산출물 또는 명시적 복합 수용조건이며, 같은 공수라는 뜻은 아니다. 한 행의 조건이 모두 충족돼야 완료다. 좁은 오류 방어 하나와 큰 미래 확장이 같은 1건이므로 이 비율을 남은 인력/개발시간 비율로 읽지 않는다.

각 행의 근거 ID는 해당 파트 문서의 코드·시험·남은 조건으로 연결된다. 선택 확장도 전체 목표에는 포함하되, 단순 제품 선택/예시 값은 제외 목록에 명시한다.

### 4.1 비기능·지원 단계·보존

상세 증거: [main.md](audit/2026-09-19/main.md).

| ID | 근거 ID | 원문 행 | 검수 요구 | 상태 | 남은 조건 / 증거 경계 |
|---|---|---|---|---|---|
| EX-001 | MA-01 | 583 | cache admission p95 MVP 30ms / Pilot 20ms | 부분 | `scripts/ops/evaluate-admission.ts`, `tests/integration/admission-measure.test.ts`. 실제 서명 캐시 경로 측정기는 있으나 완료된 대표 부하 결과 없음. 1만 identity 실험은 PARTIAL_FAILED. |
| EX-002 | MA-02 | 584 | indexer admission p95 MVP 250ms / Pilot 150ms | 부분 | 같은 실제 EVM/HTTP 측정기와 CI smoke. 운영 indexer 및 대표 부하 p95 미검증. |
| EX-003 | MA-03 | 585 | RPC fallback p95 MVP 1.5초 / Pilot 800ms | 부분 | `apps/gateway/src/admission-fallback.mjs`, `packages/contracts-sdk/src/transport.mjs`의 총 시간 예산은 구현. 타임아웃 설정은 지연 SLO 달성 증거가 아님. |
| EX-004 | MA-04 | 586 | 100MB 이하 패키지 정적 분석 시간 목표 | 부분 | 정적 scanner·실측 fixture 결과 있음. 다양한 크기/언어/의존성 표본의 60초 및 p95 90초 수용 결과 없음. |
| EX-005 | MA-05 | 587 | 실제 AI 의미 분석 p95 45초 / 20초 | 부분 | `ai-transport.mjs` deadline·usage 기록/계약 HTTP 검증. 실제 외부 모델의 대표 표본 latency 미측정. |
| EX-006 | MA-06 | 588 | 샌드박스 검사 3–10분 / p95 10분 | 부분 | native Linux 검사 성공 이력과 timeout 있음. 대표 패키지군의 반복 분포/처리량 검증 없음. |
| EX-007 | MA-07 | 589 | 격리 event→Gateway 차단 p95 30초 / 15초 | 부분 | 두 Gateway 차단·호출 직전 상태 재검사 검증. 다음 호출 없는 지속 세션의 즉시 중단 및 반복 전파 분포 미측정. |
| EX-008 | MA-08 | 595 | Pilot API 99.5% / Production 99.9% 가용성 | 미완료 | readiness·metrics 코드는 존재하지만 운영 기간/오류 예산/가용성 달성 증거 없음. |
| EX-009 | MA-09 | 598 | 최소 두 독립 RPC에서 폐기 기록 재구성 | 부분 | 복수 RPC failover와 reorg/reconcile 테스트 있음. 두 독립 외부 제공자에서 재구성한 운영 증거 없음. |
| EX-010 | MA-10 | 617, 871–876 | 외부 LLM에 전체 소스·환경·고객 데이터 비전송 | 부분 | scoped Node v2는 provenance·합집합 disclosure budget·고정 DTO와 zero-call 거부 회귀를 구현. 전체 호출 경로가 v2로 바뀐 것은 아니며 OCI v2는 별도 브랜치. 알려지지 않은 민감 데이터의 완전한 판별도 아님. |
| EX-011 | MA-11 | 793 | PyPI wheel/sdist 입력 지원 | 미완료 | 현재 resolver는 npm/tarball/OCI. OCI 안의 Python 텍스트 지원은 PyPI 수집·설치 adapter가 아님. |
| EX-012 | MA-12 | 794 | macOS·Windows Gateway adapter | 부분 | Node 기반 stdio/HTTP demo는 Windows 회귀가 있으나 attested runtime의 지원 실행 환경은 Linux Docker. macOS·Windows native 정책 adapter/검증 matrix 미완성. |
| EX-013 | MA-13 | 795 | private package registry OIDC | 미완료 | `registry-broker.mjs`는 고정 공개 registry metadata broker. GitHub CI의 OIDC 서명은 후보 private registry OIDC 입력이 아님. |
| EX-014 | MA-14 | 796 | remote Streamable HTTP metadata pinning | 미완료 | 공개 `/mcp` 서버는 제공자 역할. 임의 원격 MCP를 pinning하는 upstream proxy·metadata-only assurance 기능과 다름. |
| EX-015 | MA-15 | 798 | 후보 artifact의 Sigstore provenance 입력 검증 | 미완료 | 자체 배포 이미지 attestation workflow와 후보 공급망 provenance 수집·검증은 별개다. |
| EX-016 | MA-16 | 802 | 재현 가능한 build 및 SLSA provenance | 부분 | 불변 입력·이미지 hash·GitHub provenance/SBOM 서명 workflow와 과거 성공 산출물 있음. 동일 입력의 bit-for-bit 재현 및 정식 수준 검증, 최신 전체 성공 미확인. |
| EX-017 | MA-17 | 803, 3716–3724 | Docker보다 강한 격리 tier (gVisor/microVM/WASI 등) | 미완료 | 현재 readonly/nonroot/cgroup/network 제한 Docker. 후보 대안 전부를 동시에 도입해야 한다는 뜻은 아니나 실제 stronger-isolation tier 없음. |
| EX-018 | MA-18 | 804 | TEE runtime attestation | 미완료 | 실제 TEE quote 검증/배포 증거 없음. Docker image digest는 TEE attestation이 아님. |
| EX-019 | MA-19 | 805, 3694 | 다기관 독립 validator 운영 | 미완료 | 별도 source·key·재검사 프로세스는 구현. 독립 기관 참여·키 관리·다양성/책임 운영 증거 없음. |
| EX-020 | MA-20 | 806 | multi-chain read 또는 canonical chain mirror | 미완료 | chain/contract domain 분리는 구현됐으나 체인 간 상태 동기화·mirror 소비 기능 없음. |
| EX-021 | MA-21 | 807 | registry/IDE vendor native integration | 미완료 | 사용자가 설정하는 MCP wrapper와 자체 HTTP endpoint는 있음. vendor 자체 제품에 들어간 integration은 없음. |
| EX-022 | MA-22 | 872–876 | 위험도별 Tier 0–3 분석 분기·추가 모델/probe | 부분 | static 무AI, scoped Node metadata/snippet·tier3 다중 실제 응답 model ID/더 많은 probe 계약 검사 구현. 전체 artifact/profile 자동 분기와 외부 모델 효율·품질 실험은 미완료. |
| EX-023 | MA-23 | 896–902 | artifact/trace/log hot·warm 보존 및 appeal hold | 부분 | 암호화 content-addressed evidence·이의제기 이력 보존 있음. 7/90일 artifact, 30/180일 trace, 30일 admission log 정책의 실제 lifecycle/hold 집행 없음. 숫자는 원문 권장값이며 정책의 존재/검증을 평가. |
| EX-024 | MA-24 | 901, 618 | raw packet/body 기본 비수집 | 완료 | `services/exfil-sink/server.mjs`: canary를 메모리에서 관찰하고 body를 전달/저장하지 않음. `tests/security/egress-proxy.test.mjs`가 raw/binary/invalid JSON canary·비노출 확인. 공개 chain은 digest만. |
| EX-025 | MA-25 | 915 | per-scan byte/DNS/domain/connection egress quota | 부분 | synthetic allowlist≤32, body≤16KiB, event≤1024, timeout·외부 기본 차단 있음. 실제 외부 목적지용 누적 byte/DNS/연결 수 예산은 별도 구현 필요. |
| EX-026 | MA-26 | 928–935, 3744–3752 | PASS 릴리스 Merkle batch 및 inclusion 기반 admission | 미완료 | action receipt batch(FR-407)는 다른 기능. 정상 릴리스 PASS batch finalization·Gateway inclusion 승인 경로는 없음. MVP 제외였지만 전체 확장 범위에는 남김. |
| EX-027 | MA-27 | 3726–3732 | Pilot OPA bundle 정책 분리 | 미완료 | 현재 versioned TypeScript 정책은 MVP 선택을 충족. OPA bundle 배포·서명·검증 adapter는 없음. |

### 4.2 Backend·Trust·확장·복구

상세 증거: [backend.md](audit/2026-09-19/backend.md).

| ID | 근거 ID | 원문 행 | 검수 요구 | 상태 | 남은 조건 / 증거 경계 |
|---|---|---|---|---|---|
| EX-028 | BE-002 | 999–1003 | UUIDv7 scan ID | 미완료 | UUIDv4 대체/마이그레이션 |
| EX-029 | BE-003 | 1011,1063 | policy alias 해석 입력 | 부분 | alias→고정 hash resolution API |
| EX-030 | BE-005 | 1089–1099 | 실제 stage별 진행률 조회 | 부분 | 단계 상태 및 측정된 진행률 |
| EX-031 | BE-006 | 1199–1211 | stage event의 독립 versioned envelope | 부분 | model/scenario/step 중복키 계약 |
| EX-032 | BE-007 | 1218–1226 | tool registry namespace/locator uniqueness 모델 | 부분 | JSON metadata 외 registry uniqueness 제약 |
| EX-033 | BE-008 | 1269–1282 | finding fingerprint unique/index 조회 | 부분 | 전용 finding 원장과 index |
| EX-034 | BE-009 | 1326–1338 | client별 admission 결정 원장 | 부분 | client hash·cache age·partitioned 영향 조회 |
| EX-035 | BE-010 | 1388 | 별도 semantic NFC representation | 미완료 | 원본과 분리된 정규화 계약 |
| EX-036 | BE-011 | 1390 | volatile metadata 별도 hash layer | 미완료 | volatile/security layer 구분 |
| EX-037 | BE-013 | 1667–1672 | package owner/repository 불일치 신호 | 미완료 | 신뢰근거와 mismatch 판정 |
| EX-038 | BE-014 | 2100,2287 | equivocation 증거 제출·event | 미완료 | 상충서명 탐지/공개 event |
| EX-039 | BE-015 | 2196–2208 | PolicyRegistry URI/tier metadata | 부분 | URI/tier/폐기시각 metadata |
| EX-040 | BE-016 | 2293–2297 | validator별 서로 다른 구현 프로필 | 부분 | A/B/C 독립 구현·규칙 집합 |
| EX-041 | BE-017 | 2317–2333 | finding 단위 선택 공개 Merkle proof | 부분 | 현재 파일 leaf에서 개별 finding leaf로 구분 |
| EX-042 | BE-018 | 2422,3338–3340 | optimistic/finalized 이중 projection | 부분 | 별도 DB/UI 필드·pending confirmation |
| EX-043 | BE-019 | 2473 | OpenZeppelin ECDSA 구현 사용 | 부분 | 검증된 library 사용/동등성 독립 감사; 단순 함수 교체 제안 아님 |
| EX-044 | BE-020 | 2866 | digest별 설치 cache | 부분 | 공유 설치 layer cache |
| EX-045 | BE-021 | 2867–2869 | quick/deep 작업 프로필 분리 | 미완료 | 실제 선택/queue/scenario 시간 프로필 |
| EX-046 | BE-022 | 2870,3151 | tenant running concurrency quota | 부분 | running slot 원자 제한 |
| EX-047 | BE-023 | 2872 | worker host 일회성 폐기 | 미완료 | container cleanup과 별개인 worker host disposable lifecycle |
| EX-048 | BE-024 | 2874,3051–3064 | backlog/age/token 기반 autoscaler | 미완료 | 관측 신호→scale 제어·실제 운영 검증 |
| EX-049 | BE-025 | 2888–2895 | model/prompt/policy/input keyed AI cache | 미완료 | semantic 단계 cache와 정확한 invalidation |
| EX-050 | BE-026 | 2911 | validator scanner version 운영 inventory | 부분 | 기관별 scanner 실행 버전 대조 |
| EX-051 | BE-027 | 2913,3227 | quorum deadline와 서명 backoff scheduler | 부분 | 자동 deadline·팬아웃·지연 상태 기록 |
| EX-052 | BE-028 | 2921 | cache 만료 jitter | 미완료 | 동시 만료 분산 |
| EX-053 | BE-029 | 2922 | 동일 admission 요청 single-flight | 미완료 | future 공유; 현재 pending fence는 대체 아님 |
| EX-054 | BE-030 | 2925 | RPC fallback process quota | 완료 | 고정 quota 대안 검증; token bucket 자체 미선택 |
| EX-055 | BE-031 | 2932 | 유효기간 기반 PASS 자동 갱신 | 미완료 | 갱신 스케줄러 |
| EX-056 | BE-032 | 2934,2463 | quorum 서명 단일 tx aggregator | 미완료 | aggregator와 contract batch; 현재 개별 tx |
| EX-057 | BE-034 | 3029–3035 | stage별 독립 queue | 미완료 | resolver/static/AI/sandbox/evidence/validator 큐 분할 |
| EX-058 | BE-035 | 3035 | stage별 concurrency | 미완료 | 각 stage 자원 상한 |
| EX-059 | BE-037 | 3077–3079 | scan in-flight single-flight | 미완료 | 다른 request key의 같은 digest future 공유 |
| EX-060 | BE-038 | 3092 | Dashboard read replica | 미완료 | 읽기 분리·replica lag 처리 |
| EX-061 | BE-039 | 3093 | scan/event 월 partition | 미완료 | partition migration·유지보수 |
| EX-062 | BE-040 | 3095 | DB connection pool | 완료 | pg Pool max10 실제 PG CI. 대규모 최적화는 별개 |
| EX-063 | BE-041 | 3098–3104 | tenant/namespace sharding | 미완료 | 실제 routing/rebalance/canonical projection 검증 |
| EX-064 | BE-042 | 3117 | object-store server-side encryption | 부분 | SDK SSE 헤더 검증만; 실제 cloud/KMS 적용·복구 미검증 |
| EX-065 | BE-043 | 3118 | immutable/versioned bucket | 부분 | conditional create만 검증; versioning/WORM 실제 bucket 없음 |
| EX-066 | BE-045 | 3122 | malware artifact와 일반 bucket 계정/IAM 분리 | 미완료 | 실제 계정·권한 분리/접근 시험 |
| EX-067 | BE-048 | 3143 | release별 전역 stateVersion stale-write fence | 부분 | local epoch/terminal journal만, projection 전역 version 없음 |
| EX-068 | BE-049 | 3149 | tenant 일일 scan quota | 완료 | transaction·동시 요청/재시도 검증 |
| EX-069 | BE-050 | 3152 | publisher burst quota | 미완료 | publisher 기준 속도/버전 상한 |
| EX-070 | BE-051 | 3153 | emergency rescan priority | 미완료 | 우선순위 큐/공정성 정책 |
| EX-071 | BE-052 | 3157 | queue age 기준 접수 지연 | 미완료 | maxQueued 429만 존재 |
| EX-072 | BE-053 | 3158 | static critical의 forensic queue 전환 | 미완료 | early fail은 있으나 forensic queue 없음 |
| EX-073 | BE-054 | 3159 | AI quota 소진 시 단계만 pending·resume | 부분 | ABSTAIN/전체 job 결과만, 단계 재개 없음 |
| EX-074 | BE-055 | 3160 | object-store 장애 연계 실행량 축소 | 미완료 | 업로드 실패와 worker admission 연계 없음 |
| EX-075 | BE-056 | 3196 | scan 비용 사전 안내 | 미완료 | 비용 견적·실측 피드백 |
| EX-076 | BE-057 | 3199 | popularity 기반 deep-scan 선택 | 미완료 | risk tier와 달리 popularity 수집/스케줄 없음 |
| EX-077 | BE-058 | 3201 | chain gas ceiling | 미완료 | tx 비용 상한·보류 상태 |
| EX-078 | BE-059 | 3201 | emergency 전용 priority wallet | 미완료 | 일반 relayer와 분리 운용 |
| EX-079 | BE-060 | 3202 | validator 월별 비용/품질 측정 | 미완료 | 기관별 비용/판정 품질 지표 |
| EX-080 | BE-061 | 3211,3221–3230 | 모든 외부 작업별 total deadline 정책 | 부분 | 주요 호출은 bounded, 문서 stage/서명/전체 작업 deadline 일관성 부족 |
| EX-081 | BE-062 | 3232 | retry jitter | 미완료 | exponential scan backoff에 jitter 없음 |
| EX-082 | BE-063 | 3265–3273 | RPC circuit breaker | 미완료 | closed/open/half-open 상태 없음 |
| EX-083 | BE-064 | 3265–3273 | AI circuit breaker | 미완료 | provider별 오류율/half-open/DEFERRED 없음 |
| EX-084 | BE-065 | 3310–3312 | grace-period orphan object GC | 미완료 | object 참조 대조/삭제 큐 없음 |
| EX-085 | BE-066 | 3319 | validator NTP/clock-skew 모니터 | 미완료 | deadline 검사만, 시간 동기 감시 없음 |
| EX-086 | BE-067 | 3330–3332 | 침해키 quarantine 영향 조사·재검증 캠페인 | 미완료 | 자동 영향 집계/운영 drill 없음 |
| EX-087 | BE-068 | 3357–3358 | worker job-scoped 단기 credential | 미완료 | host worker가 DB/evidence/signing 설정 공유 |
| EX-088 | BE-069 | 3360 | kernel 경보 기반 node cordon/폐기 | 미완료 | 자동 격리·운영 검증 없음 |
| EX-089 | BE-070 | 3361 | 침해 node 산출 scan 전체 신뢰철회/재검증 | 미완료 | node→scan provenance/사고 orchestration 없음 |
| EX-090 | BE-071 | 3362 | 침해 후 base/runtime 재빌드 | 부분 | CI image build는 존재. 침해 대응 발동·검증 훈련 없음 |
| EX-091 | BE-072 | 3363 | 격리 forensic snapshot | 미완료 | 계정 분리 보관·접근/삭제 절차 없음 |
| EX-092 | BE-073 | 3386 | 서명 break-glass 감사 | 완료 | private reason/identity/expiry/1회 소모 시험; normal verdict 유지 |
| EX-093 | BE-074 | 3395 | DB RPO≤5분/RTO≤1시간 달성 | 미완료 | dump drill은 수치 SLA 증거 아님 |
| EX-094 | BE-075 | 3396 | evidence RPO≤15분/RTO≤4시간 달성 | 미완료 | 운영 측정 없음 |
| EX-095 | BE-076 | 3397 | raw trace RPO≤1시간/RTO≤24시간 달성 | 미완료 | trace 보존·복원 검증 없음 |
| EX-096 | BE-077 | 3400 | PostgreSQL PITR | 부분 | dump/restore는 있음, WAL 기반 특정시점 복원 없음 |
| EX-097 | BE-078 | 3401 | object cross-region replication | 미완료 | 설정/실제 복구 없음 |
| EX-098 | BE-079 | 3402 | IaC 재해 재배포 | 부분 | Compose는 있으나 외부 infra+state+key 복구 drill 없음 |
| EX-099 | BE-080 | 3403 | validator key encrypted/HSM recovery | 미완료 | 실제 키복구 절차·훈련 없음 |
| EX-100 | BE-081 | 3404 | 분기별 restore drill | 미완료 | 단발 CI empty DB restore와 반복 운영은 다름 |
| EX-210 | SUP-01 | 2124–2133,4077–4109,5831–5839 | Base Sepolia V2 배포·source verification·주소/tx/explorer 증빙 | 부분 | Backend B49 + Frontend DV13/PT11. 로컬 EVM·배포 스크립트만, 최신 공개 테스트넷 영수증/소스 검증 없음. |
| EX-211 | SUP-02 | 2477–2479,4111–4123 | 컨트랙트 property/invariant fuzz campaign | 미완료 | Backend B69 + Frontend DV13. 결정론적 Node EVM tests는 있으나 property/fuzz runner 실행 증거 없음. |

### 4.3 추가 분석·평가·윤리

상세 증거: [security-ai.md](audit/2026-09-19/security-ai.md).

| ID | 근거 ID | 원문 행 | 검수 요구 | 상태 | 남은 조건 / 증거 경계 |
|---|---|---|---|---|---|
| EX-101 | S02 | 1728–1765 | 별도 behavior manifest의 목적·data class·FS/network/process/env/retention 전체 계약 | 부분 | legacy `manifest.json`의 tools/declaredEgress/entrypoint만 직접 계약. 예시 전체 `mcp-shield.behavior.json` schema/집행 없음. |
| EX-102 | S10 | 1778–1779 | 목적 외 타도구 호출·타입 외 추가 데이터 요구 탐지 | 부분 | 재귀 parameter description lexical 및 AI scope claim은 존재; 체계적 목적/타입 의미 detector 검증 미완료. |
| EX-103 | S11 | 1780 | trusted-tool collision/일반명 shadowing 검사 | 미완료 | 중복 tool 이름 거부는 있음. 독립 trusted catalogue와 의미 충돌 비교 detector/평가 근거 없음. |
| EX-104 | S13 | 1782 | raw/rendered 차이 시각 보고 | 부분 | raw hash·codepoint 신호는 있음; 일반 Markdown/HTML rendered-vs-raw 비교 보고 미완료. |
| EX-105 | S20 | 1794 | scheduled task/startup persistence 정적 탐지 | 미완료 | read-only/nonroot 제약은 존재하나 persistence-specific source detector·fixture 없음. |
| EX-106 | S24 | 1816 | 새로운 environment variable diff | 미완료 | environment digest 변경은 탐지하나 이름별 새 env semantic diff 제공 없음. |
| EX-107 | S26 | 1820 | output hidden instruction/resource-link 변화 | 부분 | outputSchema diff 있음; runtime output 의미 변화 비교와 연쇄 주입 탐지 전체는 없음. |
| EX-108 | S33 | 1867,1875–1880 | 같은 입력의 별도 Analyzer/Critic 재평가+deterministic verifier | 완료 | blind context와 role prompt hash; Node v2 tier3 요청/응답 model 다양성 검사. OCI v2는 미통합. |
| EX-109 | S35 | 1869 | prompt/model/temperature/seed provenance 기록 | 완료 | AI metadata에 promptHash/model/responseModel/requestedAt/PROVIDER_DEFAULT/NOT_REQUESTED. 모델 버전 고정 실험은 E18. |
| EX-110 | S39 | 1887 | 입력/출력/전체 호출 예산 고정 | 완료 | transport256KiB/timeout/output-token ceiling + scoped64KiB/25%/union+total timeout, zero-send 회귀. |
| EX-111 | S40 | 1888 | 설명 생성을 판정 이후 별도 경로로 분리 | 미완료 | explanation이 riskClaim 응답 안에 포함됨. 별도 post-decision renderer/model stage 없음. |
| EX-112 | S42 | 1921–1922 | 최소/빈/경계/큰 입력 테스트 선택 | 부분 | bounded normal/adversarial plans, schema bounds·oversize 거부 존재. 모든 도구의 edge coverage 자동 생성 없음. |
| EX-113 | S44 | 1925–1926 | 다중 trusted/malicious tool shadowing·output→다음 call 전파 시험 | 미완료 | 현 agent harness는 단일 turn tool-decision. multi-turn tool-output poisoning 시뮬레이션 없음. |
| EX-114 | S49 | 1965 | synthetic CA endpoint TLS inspect | 미완료 | HTTP 통제 proxy/CONNECT 제한은 TLS 해독 관찰이 아님. |
| EX-115 | E02 | 4807 | 독립 공격 표본의 poisoning recall 및 explicit ≥90% 목표 | 부분 | MCPTox static review 126/485=25.98%. 실제 모델 전체 recall≥90% 달성은 아님(E28 포함). |
| EX-116 | E03 | 4808 | 독립 정상 표본 FPR 및 ≤5% 목표 | 부분 | 실제 독립 benign 분모 미확보(E29 포함). |
| EX-117 | E04 | 4809 | version rug-pull 발견 시간 실측 | 부분 | update/canary fullcycle 회귀·scan timing 존재. 다양한 rug-pull 분포별 detection latency 측정 부족. |
| EX-118 | E05 | 4810,4892–4899 | static/AI/sandbox 기여도 6구성 ablation | 미완료 | 개별 tests와 full run은 6-arm 동일 dataset 실험이 아님. |
| EX-119 | E09 | 4819 | MCPTox subset 출처/version/hash 및 사용 조건 관리 | 완료 | REALDATA upstream commit/hash, NO_EXPLICIT_LICENSE_FOUND, 원문 미재배포. 명시 라이선스 승인 완료는 아님. |
| EX-120 | E10 | 4823 | implicit poisoning 사례 기반 평가 | 부분 | implicit-scope synthetic miss 기록. MCP-ITP 관련 다양한 동작·모델 평가 부족. |
| EX-121 | E11 | 4827–4832 | benign/attack unit corpus 30건과 출처 확인된 실제 benign corpus | 부분 | 단위 metadata corpus16건(DV22), 실제 정상 라벨 표본 부족. 외부 공격485건은 benign 분모가 아님. |
| EX-122 | E13 | 4840–4841 | delayed/environment-conditional behavioral corpus | 부분 | timeout/환경 제한 테스트 존재. time-bomb·환경별 발화 탐지 실험 행렬 없음. |
| EX-123 | E15 | 4847–4856 | 2인 독립 label·불일치 합의·6-label 규격 | 미완료 | REALDATA explicitly author labels; corpus independent double labeling pending. |
| EX-124 | E17 | 4863–4868 | 동일 데이터셋의 Precision/F1 및 agent ASR·감소율 측정 | 부분 | confusion/recall/precision/FPR 및 harness ASR 존재. 동일 independently labeled 외부 dataset의 전체 지표, F1 aggregate 부족. |
| EX-125 | E18 | 4910–4916 | 동일 과제·safe/poisoned·실제 sink/action trace 기반 agent harness | 완료 | EVAL paired single-turn harness, 실제 Docker local model-contract 회귀. 자유 다중턴 agent 또는 외부모델 품질 결과가 아님. |
| EX-126 | E19 | 4916–4919 | 모델 버전/temperature/seed 조건 통제·사례별 여러 run 실측 | 부분 | metadata와 --runs, seed NOT_REQUESTED 기록. 실제 모델 paired 반복 측정 미실행. |
| EX-127 | E21 | 4881–4886 | No-defense/hash-only/static/full 4 baseline 비교 | 미완료 | paired no-defense/scanner-policy와 static 결과가 있으나 한 실험의 네 baseline 및 chain admission full 비교 없음. |
| EX-128 | E22 | 4925–4929 | hot/1만 uniform×95/50/0cache×RPC 정상/지연/장애×p50/p95/p99/error | 부분 | LOAD 18cell 계획 중15 검증,16번째 48!==0 assertion, 최종measurement없음. 성공으로 집계 금지. |
| EX-129 | E23 | 4933 | 1/10/100MB scan throughput | 부분 | OCI100MB native import 수용과개별sourcebudget 테스트. 공통 scan-throughput 행렬의 측정은 아님. |
| EX-130 | E24 | 4934 | dependency10/100/1000 throughput | 미완료 | closure functionality는 있음; dependency-scale measurement 증거 없음. |
| EX-131 | E25 | 4935 | sandbox scenario1/5/20 throughput | 미완료 | probe2..8 bounds 및 normal/adversarial 실행. 1/5/20 성능 비교 없음. |
| EX-132 | E26 | 4936–4937 | worker concurrency별 queue-age/resource 측정 | 부분 | SQL workers/queue metrics 있음; sweep benchmark 완료 aggregate 없음. |
| EX-133 | E27 | 4941–4944 | 체인 register/PASS/quarantine/revoke gas·확정시간·indexer lag 실측 | 부분 | local EVM helper 있음. 같은 환경의 완결 표와 실제 테스트넷 수치 없음(E08 포함). |
| EX-134 | E32 | 4960 | E2E demo10/10 | 완료 | Main기록 `0351567` CI 반복 데모 성공. 당시 legacy bounded 흐름이지 새OCI2/실모델에 대한결과아님. |
| EX-135 | E33 | 4976–4985 | commit/dataset/model/prompt/policy/image/chain/hardware/seed/rawaggregate 재현성 | 부분 | 각 report/source provenance 다수 존재. 모든 defense/실험을통일한metadata+rawaggregate묶음 부족, LOAD 실패명시. |
| EX-136 | R01 | 5350–5361 | 위험별 조기신호·책임자·완화책 운영 등록부 | 부분 | 원문/implementation plan에 한계, no-secret/AI-onlywarn/testvectors 구현. 실제 책임자 승인·주기 검토·alert 연결 운영 증거 없음. |
| EX-137 | R04 | 5381–5385 | maintainer/registry 연락·최소정보·긴급summary·패치협의·법적 범위 runbook | 미완료 | 실제 coordinated disclosure workflow/runbook 증거 확인 못함. 실제 취약점이 없어 연락 수행 자체는 요구하지 않음. |
| EX-138 | R07 | 5394–5395 | 학교/대회 규정확인·연구범위 밖 persistence/credential 접근 금지 | 부분 | synthetic scope와 runtime격리 구현. 규정 검토·승인 기록 없음. |
| EX-139 | R09 | 5399 | 낮은entropy 민감값 fingerprint의 salt/HMAC/범주화 | 부분 | 공개 allowlist/category/count와 randomcanaryhash 있음. A10 요구 child-secret HMAC fingerprint 전용 경로는 없음. |

### 4.4 Gateway·운영·개발·제출

상세 증거: [frontend-gateway-ops.md](audit/2026-09-19/frontend-gateway-ops.md).

| ID | 근거 ID | 원문 행 | 검수 요구 | 상태 | 남은 조건 / 증거 경계 |
|---|---|---|---|---|---|
| EX-140 | FG06 | 2576–2586 | tier·조직/namespace/validator allowlist·host 추가 path/domain 제약 | 부분 | 세분화된 조직 policy tier/namespace 허용목록·host 제약 병합 엔진은 전부 연결되지 않음 |
| EX-141 | FG08 | 2588–2621 | auth profile·scope·anonymous 여부별 surface attestation | 미완료 | 원문 MVP 공개 기본 목록과 pilot 사용자별 surface를 구분. 이 확장은 기본 FR 분모에 중복 가산하지 않음 |
| EX-142 | FG10 | 2623–2636 | drift 운영 이벤트 전송→긴급 rescan | 부분 | control-plane 이벤트 접수·자동 긴급 재검사 연결 없음, running call complete/cancel 정책 선택도 없음 |
| EX-143 | FG11 | 2638–2651 | READ_PUBLIC/PRIVATE·WRITE_LOCAL/EXTERNAL·DESTRUCTIVE·FINANCIAL 별 scope/확인/fresh check | 부분 | financial/delete 사용자 확인·scope/path별 강제·6분류 전부 자동판별하는 call policy는 없음 |
| EX-144 | FG13 | 2653–2681 | cache key·TTL·revoked permanent·읽기만 stale | 부분 | 상태별 30s–5m/15–60s negative TTL·event push invalidation의 문서 표 전체와는 다름 |
| EX-145 | FG15 | 2683–2718 | 승인 runtime의 세분화 파일/네트워크 허용 및 secret broker | 부분 | 격리 기본값은 구현. 실제 서비스 endpoint·session write scope·단기 secret broker는 미연결. FR303의 미검증 격리와 구분. |
| EX-146 | FG20 | 2795–2813,5546–5548 | evidence destination/policy/마지막 안전 버전·안전대안 선택 UX | 부분 | 차단 CLI에 마지막 안전 버전 추천/원클릭 rollback·권한 확인된 상세 대안은 없음 |
| EX-147 | FG21 | 2815–2821 | Gateway bypass 경계 공개·production 기본 우회 금지 | 부분 | 조직 endpoint management·서명 managed config/process policy 강제는 운영 구축 안 됨 |
| EX-148 | OB03 | 3535–3557 | resolve/download/canonical/static/AI/probegen/sandbox 각 하위 단계 상세 span | 부분 | 다운로드·정규화·probe 생성·normal/adversarial별 세밀한 span 전부가 아님 |
| EX-149 | OB04 | 3506–3533 | 구조화 로그·trace 연결 | 부분 | 모든 프로세스 로그가 제시 JSON 공통 필드로 통일되지는 않음; console diagnostic도 존재 |
| EX-150 | OB05 | 3506–3533 | raw credential/canary/prompt/PII 비노출, private evidence | 완료 | 완료는 테스트된 경로 한정, 임의 조직 로그/외부 SIEM 전체 감사 아님 |
| EX-151 | OB06 | 3453–3465 | admission availability 99% MVP/99.9% pilot | 미완료 | 운영 시간창 가용성·error budget·기간 실측 없음 |
| EX-152 | OB10 | 3453–3465 | known REVOKED unsafe allow =0 | 부분 | 운영 전체 호출의 0건 불변식 metric·관측 기간/alert 없음 |
| EX-153 | OB11 | 3467–3476 | scan p95 <5m | 부분 | 다양한 실제 패키지 workload의 end-to-end 목표 검증 없음 |
| EX-154 | OB12 | 3467–3476 | queue p95 <2m | 미완료 | queue wait histogram/대표 부하 실측 없음 |
| EX-155 | OB13 | 3467–3476 | 운영 sandbox timeout 비율 <10% | 부분 | 운영 분모·timeout rate 보고서 없음 |
| EX-156 | OB14 | 3467–3476 | 운영 중복 실행 비율 <5% | 부분 | 실제 중복 실행률의 관측 기간·분모 없음 |
| EX-157 | OB15 | 3467–3476 | 운영 evidence integrity 검사율 100% | 부분 | 검증 기능은 있으나 운영 evidence 전체 건수 대비 100% 측정 아님 |
| EX-158 | OB17 | 3478–3484 | deterministic reproduction rate·mean quarantine·appeal overturn rate | 부분 | 일반 공격/신고 모집단·처리시간/번복 비율 측정 없음 |
| EX-159 | OB18 | 3486–3504 | admission decision/latency·stage duration/error 지표 | 완료 | 4종 기본 instrument 구현만 완료 |
| EX-160 | OB19 | 3486–3504 | HTTP 요청·cache hit/miss·queue age 지표 | 부분 | 제시 신호별 dedicated counter/histogram/Grafana panel 없음 |
| EX-161 | OB20 | 3486–3504 | sandbox active/killed·findings counter | 부분 | 집계 metric과 운영 collector 패널 없음 |
| EX-162 | OB21 | 3486–3504 | LLM tokens·cost·quota metric | 부분 | 실제 비용/기간별 집계·알림 dashboard 없음 |
| EX-163 | OB22 | 3486–3504 | validator attest·chain tx·indexer lag·revocation propagation metric | 부분 | 전용 outcome/lag/propagation signal과 운영 검증 없음 |
| EX-164 | OB23 | 3559–3573 | 운영 dashboard queue/age·capacity·LLM·RPC/indexer·validator | 부분 | Grafana 기본 지연·판정·stage 패널 외 queue/cost/lag/validator 전체 요건 부족 |
| EX-165 | OB24 | 3575–3581 | 보안 dashboard findings/quarantine/revoke·namespace·drift·dest·breakglass | 부분 | namespace별 집계·runtime drift/egress destination/breakglass 운영 화면 연결 없음 |
| EX-166 | OB26A | 3589–3601 | revocation propagation p95 초과 5분 알림 / OB09 운영 후속 | 미완료 | metric·threshold·fault injection·runbook 연결 |
| EX-167 | OB26B | 3589–3601 | known-revoked allow >0 즉시 알림 / OB10 운영 후속 | 미완료 | 실제 잘못된 허용 탐지 counter와 수신 검증 |
| EX-168 | OB26C | 3589–3601 | sandbox escape signal 알림 | 미완료 | signal 수집·즉시 대응 runbook/수신 |
| EX-169 | OB26D | 3589–3601 | validator equivocation 알림 | 미완료 | 충돌서명 관측 rule·수신 검증 |
| EX-170 | OB26E | 3589–3601 | indexer lag >20 blocks 알림 / OB22 | 미완료 | latest/confirmed head 차이 metric·지속조건 검증 |
| EX-171 | OB26F | 3589–3601 | queue oldest >10분 알림 / OB12 | 미완료 | oldest age metric·실제 대기 주입 |
| EX-172 | OB26G | 3589–3601 | LLM 비용 급증 알림 / OB21 | 미완료 | 실제 사용량 집계·baseline·수신 |
| EX-173 | OB26H | 3589–3601 | benign FPR 급증 알림 / OB16 | 미완료 | labeled denominator·baseline·rule |
| EX-174 | OB26I | 3589–3601 | object hash mismatch 알림 | 미완료 | 전용 counter·사건 연결·수신 |
| EX-175 | OB26J | 3589–3601 | 알림별 runbook/운영 Alertmanager 실제 사람에게 전달 | 미완료 | 승인된 수신 경로·secret·복구/중복억제·실제 수신 drill |
| EX-176 | OB29 | 3624–3634 | propagation 지연 9단계 runbook·긴급 signed denylist | 부분 | Redis/pubsub 미사용 대체 진단, host heartbeat/적용비율·긴급 denylist 배포·postmortem drill 미완료 |
| EX-177 | DV03 | 4051–4075,4518–4524 | TS/Python canonical bytes/hash vectors(10개 이상·NFC/NFD/BOM/zero-width/number/null/key/large schema) | 부분 | Python 구현·cross-language 같은 vector CI 없음; 10개 named fixture를 갖춘 독립 vector corpus도 미발견 |
| EX-178 | DV04 | 3804–3880,4516–4519 | README·architecture/threat-model·ADR·protocol/finding schemas·sample report·demo fixture | 완료 | 파일 존재/내용+관련 E1/E2. 최신 아키텍처 설명은 일부 오래된 MVP 표기가 있어 DV05 참조 |
| EX-179 | DV07 | 3930–3962 | one-command stack + Docker socket 금지/허용된 runner | 부분 | dynamic worker의 제한된 runner daemon 운영 없음; 최신 Compose build 수정 후 Linux 재실행 남음 |
| EX-180 | DV08 | 3964–3996 | config 우선순위·더 엄격한 override·emergency deny | 부분 | default→env→tenant→host→emergency deny의 일관된 병합 체계/서명 bundle 없음 |
| EX-181 | DV09 | 3964–3996,4185–4193 | secrets/validator key 분리·repo no secret | 부분 | 운영 secret manager/HSM·branch protection·모든 새 HEAD secret gate 미검증; public demo keys는 synthetic으로 명시 |
| EX-182 | DV10 | 3998–4005 | migration version·재구축·backup/rolling schema | 부분 | 운영 PITR/RPO/RTO·암호화 evidence+key 동시 복구·rolling upgrade drill 미완료. Backend 소유 중복 |
| EX-183 | DV11 | 4007–4017 | schema first·TS/Pydantic/OpenAPI/eventvalidator 생성·additionalProperties false·v1/v2 | 부분 | TS 타입 수동/Python없음, 자동 OpenAPI/Pydantic/schema compatibility generation pipeline 없음 |
| EX-184 | DV12 | 4019–4049 | plugin timeout/memory/outputschema·실패 격리 | 부분 | 제시 Python plugin interface는 예시이나 범용 plugin별 자원제어/격리 프레임은 없음. Security 소유 중복 |
| EX-185 | DV14 | 4111–4123 | PR typecheck/unit/schema/canonical/contract smoke | 부분 | lint 전용 command, schema backward-compat diff, contract fuzz 없음; TS/Python vectors는 DV03 |
| EX-186 | DV15 | 4111–4123 | PR container·secret·license scan | 부분 | 최신 verify 선행실패로 일부 skipped; license inventory≠승인 allow/deny 정책 |
| EX-187 | DV17 | 4134–4141 | release tag·changelog·signed artifacts·address/config manifest·migration/rollback plan | 부분 | 최신 release tag/changelog/versioned release bundle 및 실제 rollback drill 미발견 |
| EX-188 | DV19 | 4169–4181 | archive bomb·symlink·traversal·malformed schema·bidi/zero-width·prompt injection·infinite child·fork/DNS·conflicting votes·reorg | 부분 | 실제 fork-bomb/DNS-tunneling 전용 named adversarial test·cross-language Unicode corpus 미발견. network-none/cgroup 존재만으로 해당 공격 실험 완료라 하지 않음 |
| EX-189 | DV20 | 4183–4193 | 보안 개발·branch protection/최소 1인 리뷰 강제 | 부분 | 규칙·lock/digest·교차 리뷰 기록은 있으나 서버의 강제 review/보호 설정 미검증. |
| EX-190 | DM03 | 4346–4390 | 3분 시연 영상 (safe→malicious→evidence→chain→두Agent→rollback) | 미완료 | 녹화·실제 실행 provenance·3분 길이 확인 필요 |
| EX-191 | DM04 | 4392–4407,4647 | 8분 deck 및 7분30초 rehearsal | 부분 | 8분 발표 대본·7분30초 실측 녹화/리허설 기록 없음 |
| EX-192 | DM05 | 4409–4436 | 발표 머신 실행 runbook·환경/장비 preflight | 부분 | PT12 포함. demo 스크립트는 있으나 발표 장비·runtime·폰트·화면·network/HDMI 확인 기록 없음. |
| EX-193 | DM06 | 4449–4472 | RPC/LLM/sandbox replay fallback·hash 확인·비실시간 명시 | 부분 | signed evidence bundle replay라고 표기/검증하는 완전 경로와 실제 timeout 리허설·explorer clip는 없음 |
| EX-194 | DM07 | 4451–4472,4498,5851 | 60초 fallback 및 60–90초 영상/GIF local 보관 | 미완료 | 녹화/오프라인 재생 확인 |
| EX-195 | DM11 | 4645–4646 | 최신 clean machine에서 README대로 전체 재현 | 부분 | 과거 fresh CI runner+10회 반복은 SE:E32. 최신 신규 v2 gate 실패 및 발표 머신 clean 재현 미검증. |
| EX-196 | DM12 | 4649–4674 | 현장 network/mentor/freeze·address/benchmark 고정·checksum·권한·operator 동기화 | 미완료 | 실제 행사 체크 기록·제출 산출물 checksum·리허설 필요 |
| EX-197 | DM13 | 4676–4733 | 3인/4인 역할·RACI | 부분 | 실제 참가자 이름·4인 Product 역할·발표/Q&A 책임자 지정 없음; RACI표는 예시 |
| EX-198 | DM15 | 4748–4790 | mentor질문·board/issue8필드·Later관리 | 부분 | 실제 프로젝트 board·issue value/threat/acceptance/owner/estimate/observability/security/demo relevance 채움·mentor 답변 기록 미확인 |
| EX-199 | DM16 | 4260–4265,4354,4364,4441 | 같은 publisher demo key로 두 버전을 실제 서명·유효성 확인 | 미완료 | 실제 publisher signing/verification fixture·변조/다른키 거부 테스트·LIVE evidence 연결 필요. EIP-712 validator 서명·admission Ed25519 서명은 publisher 출처 서명의 대체가 아님. DM01 요약과 이 원자를 중복 집계하지 않음 |
| EX-200 | PT01 | 4991–5012,5868 | 10p 제안서 원고·필수항목·최신 주장·팀/출처/QR 완성 | 부분 | PT01–05 통합. HTML은 있음. 오래된 수치·팀/소속/GitHub placeholders·정확한 한계/출처·출력 가독성 검수 남음. |
| EX-201 | PT06 | 5856,5870 | 실제 PPT와 PDF 생성·둘다 열기·PDF page count | 미완료 | PPT/PDF export·열기·11장(표지+10) 실측 필요 |
| EX-202 | PT07 | 5822–5824 | repo 공개 전 .env/key/RPCtoken 제거·secret scan·fixture 외부endpoint 점검 | 부분 | 최신 HEAD 전체 secret gate 및 git history 공개전 점검을 이번 감사에 실행하지 않음 |
| EX-203 | PT08 | 5825 | LICENSE + third-party notices | 미완료 | 프로젝트 공개 license 선택·의존성 notices 작성(Trivy license 목록은 대체 아님) |
| EX-204 | PT09 | 5826 | SECURITY.md 신고 이메일/범위 | 부분 | 실제 비공개 신고 이메일/접수 URL 없음 |
| EX-205 | PT13 | 5857–5858,5871 | QR 접근·public/심사권한·incognito 링크시험 | 부분 | 모든 제출 링크/QR를 로그아웃 시크릿으로 점검한 기록 없음 |
| EX-206 | PT15 | 5872–5874 | 파일명규칙·제출완료화면·checksum/backup | 미완료 | 사용자 제출확인·규칙검증·checksum/보관 필요. 자동 제출 권한을 추론하지 않음 |
| EX-207 | AD01 | 5263–5279 | 개발자 CLI·기업 SDK·Registry badge/API·독립 validator 도입 | 부분 | packaged public CLI 배포/기업 강제 SDK·SIEM/EDR, scope/policy/expiry badge embedding, 실제 community/독립기관 참여 없음 |
| EX-208 | AD03 | 5314–5328 | Observe→Warn→Enforce 단계적 rollout | 부분 | 실제 MCP 운영에서 observe-only inventory·warn 사용자승인·조직 rollout 제어 없음; inspect dry-run과 구분 |
| EX-209 | AD04 | 5330–5338 | 미검증/태그감소·review시간·revoke host비율·bypass·MTTC·중복scan절감 측정 | 미완료 | 도입 전후 baseline/tenant host inventory·모든 7지표의 운영 측정 없음 |
| EX-212 | SUP-03 | 2679–2681 | cache 상태의 정기 RPC 교차검증 | 미완료 | FG14: 필요시 direct RPC 경로와 별개인 주기 검증 scheduler 없음. |
| EX-213 | SUP-04 | 3603–3622 | 선택 action receipt의 자동 주기 batch anchoring | 미완료 | OB28: 수동 local/EVM anchor는 FR407 완료. 자동 운영 주기는 별도 미구현. |
| EX-214 | SUP-05 | 4125–4132,4627–4647 | 최신 전체 통합본 공개 배포와 배포 후 E2E | 부분 | 배포 설정/기존 Railway demo는 있음. 최신 master control-plane·scoped 버전 배포/검증 없음(DV16). |

### 4.5 중복 제거·대안 처리 기록

파트 문서의 136 대조행·85 후보·105 관측행·120 관측행을 그대로 더하지 않았다.
다음 관측은 삭제한 요구가 아니라 기존 FR/EX에 귀속한 **비집계 행**이다.
아래 근거 ID는 위 EX 표의 근거 ID로 찾으면 된다.

| 상세 관측 ID | 최종 귀속 또는 비집계 이유 |
|---|---|
| BE-001 | FR-003/004 및 BE-007. namespace 부족은 보존. Tool ID SHA-256/Keccak 식 선택 차이를 새 기능으로 세지 않음. |
| BE-004 | callbackUrl은 API 예시의 선택 필드. 별도 필수 webhook 요구가 아니므로 비집계; 미구현 사실은 Backend에 보존. |
| BE-012/033/036/046 | 각각 FR-006의 ref 경계, FR-405 원자성, FR-404 stage/DLQ 부족, FR-403 object 접근 경계. |
| BE-044/047 | presigned URL/Redis는 수단 선택. 현재 인증 API/SQL queue/서명 로컬 cache 대안. 실제 분산 cache 부족은 BE-028/029/048에 남김. |
| BE-082/083/084/085 | 각각 FR-003/004+MA-23, FR-008, BE-005/061, FR-108/303. SQL 테이블명·필드 예시와 같은 기능을 다시 세지 않음. |
| S01 | FR 전체 수직 흐름 조합. 최신 scoped 실패는 FR-111 및 아래 CI 경계. |
| S03–09/S12/S14–19/S21–23/S25/S27 | FR-101–104/109/110. hidden rendered 차이는 S13, 일반 언어 부족은 FR-103 부분. |
| S28–32/S34/S41/S43/S45 | FR-105/106/111/113. probe coverage 추가 조건은 S42. |
| S36/S37/S38 | BE-025 AI cache, MA-10 전송 제한, MA-22 tiering. |
| S46–48/S50–58 | FR-107–113/201/206/207/305 및 MA-24. DNS/syscall 부족으로 FR-109/110/112 부분. |
| E01/E20/E34 | E33 실험 재현성, E09 비노출·hash 기반 출처. |
| E06/E07/E31 | MA-01/02/03/07 및 OB11 시간 목표. 같은 경로의 장별 수치 충돌은 아래에 보존. |
| E08/E28/E29 | E27 체인 측정, E02 recall/목표, E03 FPR/목표. |
| E12/E14/E16/E30 | FR-001/006/103/109/110/208/302의 fixture·수용 시험. |
| R02/R13 | PT01 최신 주장/한계/목표와 실측 구분 검수. |
| R03/R05/R06/R08/R10/R11/R12 | FR-403, FR-110+R07, BE-045/068, FR-209, FR-201/202, FR-402/406, FR-113/206. |
| FG01–05/FG07/09/12/14/16/17/19 | 대응 FR-001–006/301–310. FG14의 정기 RPC 교차검증은 SUP-03. |
| FG18/FG22 | MA-14 remote assurance, BE-073 break-glass. |
| OB01/02/25/27/28 | FR-401/402/407. 주기 anchor는 SUP-04. |
| OB07/08/09/16 | MA-01/02/03/07 및 E02/03/17. |
| OB26 | 요약 제외; 9종 rule과 수신 검수 OB26A–J만 집계. |
| OB30 | 종합 health는 구현된 부가 기능. 원문 밖의 독립 요구를 만들어 완료 건수를 늘리지 않음. |
| DV01 | Node/npm/SQL queue/Ganache 등의 기능 대안. 원문 선호 도구 이름별로 미완료 수를 늘리지 않음. |
| DV02/05/06 | FR-005 직접 JCS 구현 금지, DV04 문서, BE-045/068+MA-19 trust 운영 경계. |
| DV13/16 | FR-201–212+SUP-01 테스트넷+SUP-02 fuzz; MA-16 provenance/build+SUP-05 최신 배포. |
| DV18/21/22 | FR 수용 테스트/우선순위 요약; 30건 corpus는 E11에 통합. |
| DM01/02/08 | FR 핵심 흐름·합성 자료. 실제 publisher 서명은 DM16 별도. |
| DM09/10/14 | PoC·7주·DoD 요약. 각 named artifact는 파트 문서 coverage와 FR/EX로 연결. |
| PT02–05 | PT01 콘텐츠·최신성·가독성·팀/출처/QR 완성. |
| PT10/11/12/14 | DV04/07+DM07, SUP-01, DM05, DM04/13. |
| AD02/05 | 사업 수익/네트워크 효과는 가정·가치 설명. LICENSE=PT08, 기관 독립=MA-19, appeal=FR-406, 발표 주장=PT01. |

원문 수치 충돌도 보존한다. cache p95는 2.5절 30/20ms, 12장 20/10ms, 17장 20ms로
다르고 폐기 전파도 30/15초·60/15초·10초가 혼재한다. 이를 세 개의 새 기능으로 세거나
가장 쉬운 값을 임의로 완료 기준으로 삼지 않았다. 같은 경로 MA-01/07에 합쳤으며
최종 목표값·환경 동결과 대표 분포 검증이 남는다. NFC 의미층과 JCS 원본 bytes 보존은
별개(BE-010)로 구분했다. 단순 역할명/예시 데이터/표현 문구의 차이는 새 기능으로 세지 않았다.

## 5. 검증·배포 경계

- 로컬 Windows Main `e55c1ab`: 전체 `npm test` 종료 0, backend+Next 기본 Turbopack build 성공.
- `1686547`: 사용자 안내 client/BFF 및 release gate 집중 검사 14 PASS, backend typecheck 성공.
- Linux [CI 35427980359](https://github.com/sihoon-0077/MCPShield/actions/runs/35427980359)는 기준 SHA `7bac78a`,
  **종료·전체 실패**다. Node 24, 실제 PostgreSQL 및 별도 빈 DB backup/restore는 성공.
  기존 OCI v1 fullcycle 2 PASS/0 SKIP, prepared v1 3 PASS(새 v2 조건부 1 SKIP)를 실제 로그에서 확인했다.
- Node 22 새 scoped scanner: **10 PASS/1 FAIL/0 SKIP**. 악성 사례가 `FAIL` 대신 `ABSTAIN`;
  `SCOPED_SEMANTIC_INPUT_OR_AUTHORITY_INVALID`, `SCOPED_PROVIDER_CONFIG_INVALID`,
  `PREPARED_SCOPED_REVIEW_INCOMPLETE`를 로그에서 확인했다.
  위치: `tests/security/scoped-prepared.test.mjs:334`.
- 별도 scoped API→독립 validator→Gateway gate: **0 PASS/1 FAIL/0 SKIP**.
  준비 결과 `DERIVED_RELEASE_CREATED`지만 `SCOPED_REVIEW_OR_OBSERVATION_INCOMPLETE`로
  `ABSTAIN`이며 기대한 `FAIL`과 다르다. `tests/api/prepared-fullcycle.test.ts:167,225`.
  두 건이 같은 근본 원인인지는 아직 진단하지 않았다. 불완전 검사를 승인한 증거는 아니다.
- 선행 실패 때문에 이 실행의 후속 Compose/Grafana/일부 isolation·production audit·secret 단계는
  **SKIPPED**다. Docker COPY 수정의 전체 Compose 재통과를 주장하지 않는다.
- 같은 SHA의 `repeat-demo` job과 실제 격리→EVM→Gateway **10회 반복 step은 성공**.
  `signed-image` job도 성공이나 실제 nonroot 이미지/HTTP MCP/취약점·license inventory/SBOM까지만
  성공했다. **provenance/SBOM 서명·검증·이미지 보관은 SKIPPED**라 최종 서명 산출물 완료가 아니다.
- 직전 [CI 35425746994](https://github.com/sihoon-0077/MCPShield/actions/runs/35425746994)는 전체 실패지만,
  기존 OCI native 전체 흐름 2 PASS, prepared npm 3 PASS, 실제 10회 반복 demo 성공 증거를 갖는다.
  그때의 dashboard COPY 누락은 수정됐지만 다른 SHA의 성공으로 최신 전체 검증을 대체하지 않는다.
- 외부 AI 품질·Base Sepolia·실제 S3/KMS·독립 기관 validator·최신 Railway 배포는 완료 증거 없음.
- 현재 공개 URL은 기존 데모. 공개 demo의 `VERIFIED/REVOKED` 표시를 최신 control plane이나
  실제 테스트넷 검증자망의 운영 상태로 해석하면 안 된다.

기준 SHA 이후 변경은 감사 문서·집계기만이다. OCI `8c13b9c`는 별도 worktree에 보존하고
합치지 않았다. 이 감사에서 신규 기능 수정·새 CI·배포·원격 push를 시작하지 않았다.
파트 문서에 남은 ‘CI 진행 중/원인 미확인’은 작성 시점 기록이며 위 종료 확인이 우선한다.

## 6. 이후 작업 원칙

이 감사가 끝나도 전체 개발 목표가 완료된 것은 아니다. 사용자 재개 지시 전에는 신규 구현을
자동으로 계속하지 않는다. 다음 단계는 감사표의 실패/부분/미완료에서 선택하며, 보안 검사를
낮추거나 mock을 실제 결과로 표시해서 완료율을 올리지 않는다.
