# Security·AI 원문 요구사항 감사 — 2026-09-19

## 범위와 판정 기준

원문: `MCPShield_전체_시스템디자인_해커톤_마스터문서.md`, SHA-256
`702268984174af450276b5292a4afccd6a4d5dce79738fe3abde41c4d30d4ea2`.
지정 범위 **1712–2090, 4794–4990, 5346–5431, 5690–5817**을 전부 읽었다.
PowerShell `Get-Content`는 마지막 빈 줄을 제외해 5,996행, 마지막 빈 줄 포함 원문 기준은 5,997행이다.
FR 매핑을 위해 원문 506–531도 확인했다.

- 통합 기준은 Main `7bac78a`. Main이 확인한 CI `35427980359`의 Node 22 step 14
  `Exercise scoped Node v2 disclosure and actual isolated probe execution`는 **실패**했다.
  해당 job은 계속 진행 중이며 상세 로그/원인은 아직 확인되지 않았다. Node scoped-v2 native
  전체 검증은 부분 상태이고, 원인 추정·안전 제한 완화·수정 구현을 하지 않는다.
- 기존 Main 기록: `0351567` / CI `35425746994`의 OCI v1 fullcycle 2 PASS,
  prepared v1 fullcycle 3 PASS, 10회 반복 데모 성공. 전체 job은 별도 Compose 누락으로 실패했다.
  이전 커밋 성공을 최신 코드 전체 성공으로 전용하지 않는다.
- 별도 브랜치 `master/security-scoped-oci-v2`의 **`8c13b9c`는 미통합 checkpoint**다.
  이 커밋의 `npm run test:security`: 132 PASS / 20 SKIP, `build:backend` PASS.
  OCI v2의 실제 loopback HTTP 및 합성 순수 평가자 테스트만 실행했고 native Docker/Trivy gate는 미실행이다.
  따라서 OCI v2 API·독립 validator·UI·실제 모델 품질 완료로 세지 않는다.
- 완료 = 해당 행의 제한된 기능·검증이 존재. 부분 = 일부 구현 또는 필수 환경/경로 검증 누락.
  미완료 = 요구 구현/측정의 증거를 확인하지 못함. 불가능한 절대 안전성 증명은 완료 조건으로 만들지 않는다.
- JSON 강제·근거 검증·전송 제한 **구현**과 실제 외부 모델의 **품질/ASR 측정**은 별개다.
  실제 유료 모델을 부르지 않았다는 이유만으로 전자를 자동 미완료 처리하지 않는다.
- 아래 원자 ID가 상세 분모 후보다. FR 요약, 수용 테스트의 반복, coverage notes는 추가 분모로 중복 집계하지 않는다.
  Backend/Gateway와 겹치는 항목은 Main이 해당 담당자의 증거와 합쳐 한 번만 센다.

상세 S/E/R 행 내부 집계: **105개 = 완료 44 / 부분 46 / 미완료 15**.
부분을 완료로 세지 않는 이 범위의 엄격 완료 비율은 44/105 = **41.90%**다.
이는 전체 프로젝트 완료율이 아니다. Main의 전 문서 중복 제거·담당자 교차 증거 반영 전
부분 소유 범위 집계이며, FR 요약과 부록 A 표를 다시 더하지 않는다.

## 근거 약어

경로는 저장소 루트 기준이다. `S/` = `services/scanner/src/`, `R/` = `services/resolver/src/`,
`TS/` = `tests/security/`, `TA/` = `tests/api/`, `TI/` = `tests/integration/`.
테스트 파일의 존재만으로 native 성공을 선언하지 않는다.

| 근거 | 실제 코드·테스트 |
|---|---|
| ING | `R/resolver.mjs`, `R/oci.mjs`, `R/npm-closure.mjs`; `TS/master-scanner.test.mjs`, `TS/npm-closure.test.mjs`, `TS/oci-resolver.test.mjs`, `TS/oci-acquisition.test.mjs` |
| ID | `S/canonical-json.mjs`, `S/evidence.mjs`, `S/tool-surface.mjs`; `TS/master-scanner.test.mjs`, `TS/prepared-binding.test.mjs`, `TS/oci-binding.test.mjs` |
| STATIC | `S/analysis.mjs`, `S/scanner.mjs`, `S/prepared-review.mjs`; `TS/master-scanner.test.mjs`, `TS/scanner.test.mjs`, `TS/prepared-scan.test.mjs` |
| AI | `S/semantic.mjs`, `S/ai-transport.mjs`, `S/probes.mjs`; `TS/semantic-review.test.mjs`, `TS/ai-provider.test.mjs`, `TS/ai-probes.test.mjs` |
| SCOPE | `S/scoped-semantic.mjs`, `S/scoped-policy.mjs`, `S/prepared-policy.mjs`; `TS/scoped-semantic.test.mjs`, `TS/scoped-prepared.test.mjs`, `TA/scoped-preparations.test.ts`, `TA/scoped-validator.test.ts` |
| OCI2 | **未통합 `8c13b9c`** `S/scoped-oci-input.mjs`, `S/oci-scan.mjs`, `S/oci-policy.mjs`, `TS/scoped-oci.test.mjs`; pure/loopback PASS, native SKIP |
| DYN | `S/sandbox.mjs`, `S/observer-preload.cjs`, `S/mcp-probe.cjs`, `S/prepared-runtime.mjs`, `S/oci-observer.mjs`; `TS/docker-sandbox.test.mjs`, `TS/prepared-observation.test.mjs`, `TS/oci-profile.test.mjs` |
| NET | `services/exfil-sink/server.mjs`; `TS/egress-proxy.test.mjs`, `TS/docker-sandbox.test.mjs` |
| POLICY | `S/prepared-policy.mjs`, `S/oci-policy.mjs`, `apps/api/src/control-policy.ts`; `TS/prepared-scan.test.mjs`, `TS/oci-sources.test.mjs`, `TA/v2-trust.test.ts` |
| EVAL | `benchmarks/evaluate.mjs`, `evaluate-metadata.mjs`, `evaluate-ai-mcp.mjs`, `agent-mcp-harness.mjs`, `mcp-attack-harness.mjs`; `TS/agent-harness.test.mjs`, `TS/ai-probes.test.mjs` |
| REALDATA | `benchmarks/results/mcptox-static-2026-09-09.json`, `benchmarks/metadata-corpus.json`, `TS/mcptox-adapter.test.mjs` |
| LOAD | `benchmarks/results/admission-matrix-10000-2026-09-09.json`, `TI/admission-measure.test.ts`; 실제 10,000-key 실행은 `PARTIAL_FAILED` |
| TRUST | `tests/contracts/release-registry-v2.test.ts`, `TA/v2-fullcycle.test.ts`, `TA/prepared-fullcycle.test.ts`, `TA/oci-fullcycle.test.ts`, `TA/appeals.test.ts` |
| PRIV | `S/redaction.mjs`, `S/sandbox.mjs`, `TA/control-plane.test.ts`, `TI/fullcycle-telemetry.test.ts` |

## FR 요약 권고 — 상세 행과 중복 집계 금지

| FR / 원문 | 권고 | 판단과 남은 조건 |
|---|---|---|
| FR-001 / 506 | 완료 | ING의 npm/tarball/OCI 입력·취득 및 계약 테스트. 모든 임의 artifact의 실행 승인까지 의미하지 않는다. |
| FR-002 / 507 | 완료 | mutable npm/OCI 참조를 exact version·manifest/config/tree digest로 고정, 변조/불변성 회귀. |
| FR-003 / 508 | 부분 | URL·namespace·retrievedAt 저장. npm maintainer는 `verified:false`, OCI `publisherEvidence:[]`; 검증된 publisher 출처 통합은 별도 필요. |
| FR-004 / 509 | 완료 | byte SHA-256 및 체인 bytes32 식별자, source/archive/prepared/image digest 구별, golden/tamper 검사. |
| FR-005 / 510 | 완료 | 공통 canonical serialization 및 순서/Unicode/변조 테스트. |
| FR-006 / 511 | 완료 | tool 정렬·전체 schema hash, pagination/duplicate/cursor/surface drift 회귀. |
| FR-101 / 519 | 완료 | 요구된 명령 패턴·비밀 경로·외부 전송·숨은 Unicode 정적 신호가 구현되고 fixture 테스트 통과. 탐지율 목표 달성은 별도 E 행이다. |
| FR-102 / 520 | 완료 | name 추가/삭제, description/input/output schema/annotation 변경·readonly downgrade diff. |
| FR-103 / 521 | 부분 | JS/Node import/egress/lifecycle/sensitive-file 제한은 구현. 언어 일반 shell/Python/난독화 분석 지점 포괄성 부족. |
| FR-104 / 522 | 완료 | npm declared/lock/installed closure SBOM 구분, dependencies/install diff; OCI detected-package native Trivy/SBOM 검증. 전체 바이너리 이해는 주장하지 않음. |
| FR-105 / 523 | 완료 | OpenAI strict schema, no-tools/store:false, 비신뢰 데이터 instruction, 제한 JSON parsing 및 injection/refusal/timeout 계약 회귀. 모델 공격 강건성 실측은 E17–E19로 별도. |
| FR-106 / 524 | 완료 | risk category/severity/confidence/evidence span/hash/recommendedProbe 검증, host citation과 허위 span 거부. |
| FR-107 / 525 | 완료 | 외부 미검증 source 실행은 일회성 Docker 경로. host LOCAL은 저장소 소유 fixture 테스트용으로 제한. native 격리 회귀는 기록된 지원 프로필 범위. |
| FR-108 / 526 | 완료 | readonly/tmpfs/no-new-privileges/cap-drop/CPU/memory/pids/deadline 및 cleanup 구현·native 지원 프로필 검증. escape 절대 부재 주장은 아님. |
| FR-109 / 527 | 부분 | 내부망·proxy allowlist·실제 인터넷 기본 차단. 모든 DNS/TCP/TLS 트래픽의 관찰 및 테스트별 동적 정책 일반화는 부족. |
| FR-110 / 528 | 부분 | 8종 무작위 dummy 주입·hash 유출 탐지. OCI 전체 파일-read syscall 및 DNS-label 전송 관찰은 없음. |
| FR-111 / 529 | 완료 | 정상/적대 synthetic 계획 생성·schema/도구/인자/경로/목적지 제한, 실제 child/native 계약 테스트. 탐지 효능 실험은 별도. |
| FR-112 / 530 | 부분 | scan bundle의 MCP/egress/Node hook 연계 존재; OCI 파일/process syscall 및 전 도구 신뢰된 통합 timeline 부족. |
| FR-113 / 531 | 완료 | AI-only는 결정론적 FAIL 근거가 아니며 불완전 review는 ABSTAIN. 독립 재실행·quorum 정책 회귀. |

## 6장: 분석·격리·정책 원자 요구사항

| ID | 원문 | FR | 요구사항 | 상태 | 코드/시험 근거 및 남은 조건 |
|---|---|---|---|---|---|
| S01 | 1724 | 101–113 | provenance→static→semantic→dynamic→policy→quorum→admission 결합 | 부분 | ING/STATIC/AI/DYN/POLICY/TRUST의 지원 v1 경로. Node v2 최신 native 통합 진행 중, OCI2 미통합. |
| S02 | 1728–1765 | 103,109,110 | 별도 behavior manifest의 목적·data class·FS/network/process/env/retention 전체 계약 | 부분 | legacy `manifest.json`의 tools/declaredEgress/entrypoint만 직접 계약. 예시 전체 `mcp-shield.behavior.json` schema/집행 없음. |
| S03 | 1768 | 109 | 선언 외 egress를 관찰하여 finding 생성 | 완료 | NET의 EGRESS_BLOCKED→UNDECLARED_EGRESS, 허용/거부 테스트. |
| S04 | 1768,1988 | 110 | 금지 데이터 읽기만으로 독립 접근 finding 생성 | 부분 | Node FS_READ/SENSITIVE_FILE_READ hook; OCI는 STATIC_IMAGE_INVENTORY_NOT_SYSCALL_TRACE. `FORBIDDEN_DATA_ACCESS` 전체 규격 대응 부족. |
| S05 | 1768,1988 | 110 | 실제 canary 전송을 critical finding으로 생성 | 완료 | 통제 sink 실제 bytes/hash 연결, DYN/NET 및 Linux canary 회귀. |
| S06 | 1774 | 101 | 모델 지향 명령 패턴 탐지 | 완료 | STATIC `metadataSignals` 정규식과 corpus. |
| S07 | 1775 | 101 | 민감 경로·credential 언급 탐지 | 완료 | STATIC의 SSH/env/AWS/wallet/browser 경로 패턴. |
| S08 | 1776 | 101 | 전송 동사와 외부 URL 근접 탐지 | 완료 | STATIC EXTERNAL_TRANSFER 및 fixture. 모든 표현 recall은 별도. |
| S09 | 1777 | 101 | zero-width/bidi/hidden markup 탐지 | 부분 | HIDDEN_UNICODE/HTML comment 존재; Markdown hidden-block 일반 렌더링 분석은 없음. |
| S10 | 1778–1779 | 101 | 목적 외 타도구 호출·타입 외 추가 데이터 요구 탐지 | 부분 | 재귀 parameter description lexical 및 AI scope claim은 존재; 체계적 목적/타입 의미 detector 검증 미완료. |
| S11 | 1780 | 101 | trusted-tool collision/일반명 shadowing 검사 | 미완료 | 중복 tool 이름 거부는 있음. 독립 trusted catalogue와 의미 충돌 비교 detector/평가 근거 없음. |
| S12 | 1782 | 101 | Unicode code point 노출 | 완료 | metadata signal에 codePoint/start/end/textHash 기록. |
| S13 | 1782 | 101 | raw/rendered 차이 시각 보고 | 부분 | raw hash·codepoint 신호는 있음; 일반 Markdown/HTML rendered-vs-raw 비교 보고 미완료. |
| S14 | 1786 | 103 | install lifecycle script 탐지·차이 표시 | 완료 | STATIC lifecycle 검사/compareRelease, installScripts=false 제한. |
| S15 | 1787 | 103 | child_process 및 shell=True 호출 지점 분석 | 부분 | Node import 정책/hook/lexical 경고; Python shell=True 구문 수준 일반 분석 없음. |
| S16 | 1788,1793 | 103 | 난독 command/encoded payload/self-extracting binary 분석 | 부분 | 미지원 binary/dynamic import 거부·ABSTAIN 가능. 실제 의미 해석/난독 변종 탐지기 없음. |
| S17 | 1789–1790 | 103 | credential enumeration/browser/keychain/wallet 코드 접근 분석 | 부분 | 선택된 JS readFile 경로/metadata 패턴. keychain·언어 일반 enumeration 포괄 검사 없음. |
| S18 | 1791 | 103 | raw socket/DNS-tunneling library 탐지 | 부분 | restricted import/egress 프로필 거부. 전언어 library/실제 DNS tunneling 탐지 없음. |
| S19 | 1792 | 103 | HTTP 목적지와 manifest 비교 | 부분 | declaredEgress 없음/host allowlist 및 runtime 관찰. 모든 source의 동적 destination 정적 복원은 안 함. |
| S20 | 1794 | 103 | scheduled task/startup persistence 정적 탐지 | 미완료 | read-only/nonroot 제약은 존재하나 persistence-specific source detector·fixture 없음. |
| S21 | 1795 | 103 | dynamic import/download-execute 제한 | 완료 | self-contained import policy, template/regex 우회 회귀, prepared offline closure. |
| S22 | 1796 | 103,108 | privileged/root 요구 거부 | 완료 | OCI config/entry 안전 검사, nonroot/caps-none 고정; 요구를 수용하지 않음. |
| S23 | 1800–1815 | 102 | 보안 의미 diff/새 outbound domain | 완료 | compareRelease egress/tool/dependency/lifecycle diff. JSON 예시 source line 표시는 필수 구조와 별도. |
| S24 | 1816 | 102 | 새로운 environment variable diff | 미완료 | environment digest 변경은 탐지하나 이름별 새 env semantic diff 제공 없음. |
| S25 | 1817–1819 | 102,104 | install 추가·자유 context schema·readonly→write 변경 표시 | 완료 | installScripts/inputSchema/annotations/readOnlyRemoved 비교. 자유 field의 별도 위험 등급 세분화는 없음. |
| S26 | 1820 | 102 | output hidden instruction/resource-link 변화 | 부분 | outputSchema diff 있음; runtime output 의미 변화 비교와 연쇄 주입 탐지 전체는 없음. |
| S27 | 1821 | 102,104 | dependency source/Git URL 변경 표시·거부 | 완료 | dependency diff + immutable registry-only lock preflight. |
| S28 | 1827–1854 | 105,106 | 구조화 위험 주장·근거·confidence·권장 probe·semanticDiff·human-review JSON | 완료 | AI strict output schema, span/hash/confidence tests; 근거 없는 주장 거부. |
| S29 | 1861–1862 | 105 | candidate JSON escape 및 비신뢰 데이터 instruction | 완료 | AI/SCOPE canonical JSON·system instruction 테스트. |
| S30 | 1863 | 105 | 분석 모델에 network/tools/memory 권한 주지 않음 | 완료 | no-tools/tool_choice:none/store:false wire contract. 외부 provider 내부 retention 계약까지 보장하진 않음. |
| S31 | 1864–1865 | 105,106 | schema output+원문 범위/hash 후처리 검증 | 완료 | AI validateSemanticReport 및 precomputed citation 변조 회귀. |
| S32 | 1866 | 105,111 | 출력 URL/명령을 임의 실행하지 않음 | 완료 | validateProbePlan/validateSyntheticToolCalls, code/shell/public destinations 거부. |
| S33 | 1867,1875–1880 | 105 | 같은 입력의 별도 Analyzer/Critic 재평가+deterministic verifier | 완료 | blind context와 role prompt hash; Node v2 tier3 요청/응답 model 다양성 검사. OCI v2는 미통합. |
| S34 | 1868,1878 | 113 | lexical/결정론적 근거와 모순되는 AI safe를 자동 승인하지 않음 | 완료 | POLICY full checks, deterministic-only failure/ABSTAIN 회귀. |
| S35 | 1869 | 105 | prompt/model/temperature/seed provenance 기록 | 완료 | AI metadata에 promptHash/model/responseModel/requestedAt/PROVIDER_DEFAULT/NOT_REQUESTED. 모델 버전 고정 실험은 E18. |
| S36 | 1884 | 105 | 동일 tool-surface 결과 캐시 | 미완료 | admission cache는 semantic-analysis cache가 아님. 검증된 source/policy/model 결합 분석 cache 확인 못함. |
| S37 | 1885 | 105 | 모든 실제 LLM 호출을 manifest/schema/security diff로 제한 | 부분 | Node scoped v2 선택+예산 구현/연결. legacy scanner는 first-12K/file(총64K), prepared/OCI v1은 loopback full-source, benchmark 별도 전송. OCI2 미통합. |
| S38 | 1886 | 105 | 작은 모델 triage→의심건 큰 모델 비용 단계화 | 부분 | tier risk/role 수·tier3 distinct model 구현; model 크기/비용 등급 자동 선택·실측 없음. |
| S39 | 1887 | 105 | 입력/출력/전체 호출 예산 고정 | 완료 | transport256KiB/timeout/output-token ceiling + scoped64KiB/25%/union+total timeout, zero-send 회귀. |
| S40 | 1888 | 105 | 설명 생성을 판정 이후 별도 경로로 분리 | 미완료 | explanation이 riskClaim 응답 안에 포함됨. 별도 post-decision renderer/model stage 없음. |
| S41 | 1892–1916 | 111 | tool-specific 정상/적대 synthetic goal+인자 생성/검증 | 완료 | AI/DYN/SCOPE 실제 local HTTP 및 child/native 계약. 제시 setup/failOn JSON 자체는 예시. |
| S42 | 1921–1922 | 111 | 최소/빈/경계/큰 입력 테스트 선택 | 부분 | bounded normal/adversarial plans, schema bounds·oversize 거부 존재. 모든 도구의 edge coverage 자동 생성 없음. |
| S43 | 1923–1924 | 110,111 | 숨은 parameter·unrelated canary 접근 관찰 | 부분 | schema 추가값 제한·canary read/exfil 관찰 있음. model-induced hidden params 효능 실험 부족. |
| S44 | 1925–1926 | 111 | 다중 trusted/malicious tool shadowing·output→다음 call 전파 시험 | 미완료 | 현 agent harness는 단일 turn tool-decision. multi-turn tool-output poisoning 시뮬레이션 없음. |
| S45 | 1927–1928 | 109,111 | network failure fallback·비허용 path/domain 실패 시험 | 부분 | 외부 domain/path 방어 및 timeout tests. 모든 candidate의 fallback endpoint 분기 자동 exercise 없음. |
| S46 | 1934–1951 | 107,108 | 일회성 제한 Docker·secret 없는 fake HOME·host/docker socket 미마운트 | 완료 | DYN readonly/nonroot/cgroup/pids/no-new-privileges/tmpfs/deadline, native tests. 숫자는 예시보다 더 제한된 프로필도 사용. |
| S47 | 1959–1963 | 109 | DNS/TCP 관찰·DNS deny·allowlist routing·IP/port/redirect 기록 | 부분 | NET/internal network/DNS deny/IP/port reject 있음; 완전 DNS/TCP/redirect chain trace 없음. |
| S48 | 1964 | 109,110 | body 원문 비저장·bounded canary/size metadata 수집 | 완료 | NET raw/binary/invalid JSON canary 처리 후 hash/count만 기록, body limit 회귀. |
| S49 | 1965 | 109 | synthetic CA endpoint TLS inspect | 미완료 | HTTP 통제 proxy/CONNECT 제한은 TLS 해독 관찰이 아님. |
| S50 | 1966–1967 | 109 | 인터넷 off·metadata/link-local/localhost escape 차단 | 완료 | internal network, allowlist 고정, host mounts 없음; 지원 프로필 native direct egress 차단. kernel escape 불가능 증명은 아님. |
| S51 | 1971–1986 | 110 | scan별 unique 8종 canary 및 무효 dummy wallet | 완료 | DYN randomBytes16+scanId+type, 8개 synthetic content, 유효 wallet secret 아님. |
| S52 | 1988 | 110 | body/header/DNS-label별 유출 탐지 | 부분 | NET body/header/URL text 관찰. 독립 DNS-label 수집은 없음. |
| S53 | 1994–1998,2008 | 112 | 파일·process·egress·MCP 하나의 scan trace | 부분 | Node hook/collector+bundle+scanId 있음. OCI는 파일 syscall 없음, command line raw 대신 hash/분류, kernel-level event 신뢰성과 전 경로 연계 부족. |
| S54 | 2012–2028 | 106,112 | 공통 Finding schema 정규화 | 완료 | schema.mjs/protocol-schema.mjs 고정 code/severity/stage/deterministic/message/evidence 검증. subject/remediation 예시 필드 그대로는 아님. |
| S55 | 2033–2039 | 113 | hash/surface/revoked 및 관측 위반 결정론적 차단 | 부분 | ID/POLICY/TRUST digest/surface/canary/status 차단 완료. publisher proof·host escape·downloaded-child 범용 관찰 부족. |
| S56 | 2041–2048 | 113 | AI-only warn/review, 독립 근거 결합 시만 영구 폐기 | 완료 | POLICY/validator verdict 회귀. false/미완료 semantic을 PASS로 바꾸지 않음. |
| S57 | 2052–2074 | 113 | default deny, 상태/TTL/identity/tier/quorum 분리 판정 | 완료 | TS 정책 대안 사용, v2 trust/admission/contract tests. OPA 자체 도입은 필수 아님. |
| S58 | 2079–2086 | 113 | emergency quarantine/2-of-3 revoke/미완료 unverified 매트릭스 | 부분 | TRUST emergency/quorum/abstain 동작 존재. AI High이나 sandbox 정상인 조건부 VERIFIED/warning 정책은 보수적으로 ABSTAIN하는 차이. |

## 17장: 평가·측정 원자 요구사항

| ID | 원문 | FR | 요구사항 | 상태 | 코드/시험 근거 및 남은 조건 |
|---|---|---|---|---|---|
| E01 | 4798–4803 | 101–113 | planned/measured와 commit/환경/N 구분 | 완료 | EVAL/REALDATA 명시; 반복 synthetic를 독립 표본/실모델 결과로 표기하지 않음. |
| E02 | 4807 | 101 | poisoning 탐지율 실측 | 부분 | REALDATA 485 poisoned-tool record,126 detected/359 missed=25.98%. static lexical만; 전체 defense 아님. |
| E03 | 4808 | 101 | 정상 tool 통과율/FPR 실측 | 부분 | 16개 synthetic corpus의 benign 있음. 독립 실제 benign label 분모 없음. |
| E04 | 4809 | 102,112 | version rug-pull 발견 시간 실측 | 부분 | update/canary fullcycle 회귀·scan timing 존재. 다양한 rug-pull 분포별 detection latency 측정 부족. |
| E05 | 4810,4892–4899 | 101–113 | static/AI/sandbox 기여도 6구성 ablation | 미완료 | 개별 tests와 full run은 6-arm 동일 dataset 실험이 아님. |
| E06 | 4811 | 113 | 두 Gateway revoke 전파 시간 실측 | 부분 | TRUST/demo/integration 측정 기반 있음. latest policy 및 전체 RPC/cache 행렬의 완료 aggregate 필요. |
| E07 | 4812 | 107–113 | Gateway 추가 admission 지연 실측 | 부분 | LOAD 실제 10k-key 실행 PARTIAL_FAILED. 최종 p95 전체 대표값으로 쓰면 안 됨. |
| E08 | 4813 | 113 | 온체인 비용 실측 | 부분 | local EVM gas 테스트/측정 코드. 실제 테스트넷/네트워크 비용·확정시간 대표 측정 없음. |
| E09 | 4819 | 101 | MCPTox subset 출처/version/hash 및 사용 조건 관리 | 완료 | REALDATA upstream commit/hash, NO_EXPLICIT_LICENSE_FOUND, 원문 미재배포. 명시 라이선스 승인 완료는 아님. |
| E10 | 4823 | 101,105 | implicit poisoning 사례 기반 평가 | 부분 | implicit-scope synthetic miss 기록. MCP-ITP 관련 다양한 동작·모델 평가 부족. |
| E11 | 4827–4832 | 101 | 실제 benign corpus + 라이선스/버전/수집일 | 부분 | 자체 CC0 author corpus, 공개 metadata 제한 표본 기록. 독립 정상 검증 corpus 부족. |
| E12 | 4836–4839 | 103,110 | safe/egress/file-read/child-process behavioral corpus | 완료 | 저장소 authored fixtures와 DYN tests. |
| E13 | 4840–4841 | 103,110 | delayed/environment-conditional behavioral corpus | 부분 | timeout/환경 제한 테스트 존재. time-bomb·환경별 발화 탐지 실험 행렬 없음. |
| E14 | 4842–4843 | 006,103 | surface drift·oversize/malformed corpus | 완료 | DYN pagination/drift/schema/source limits 회귀. |
| E15 | 4847–4856 | 101–113 | 2인 독립 label·불일치 합의·6-label 규격 | 미완료 | REALDATA explicitly author labels; corpus independent double labeling pending. |
| E16 | 4858 | 109,113 | 합법적 외부전송과 악성 행동 구분 | 완료 | NET declared allowlist/mock email 정상, metadata 신호만으로 revoke 불가. 실사용 다양성은 E03. |
| E17 | 4863–4868 | 101–113 | TPR/FPR/Precision/F1/ASR absolute·relative 산식과 결과 | 부분 | confusion/recall/precision/FPR 및 harness ASR 존재. 동일 independently labeled 외부 dataset의 전체 지표, F1 aggregate 부족. |
| E18 | 4910–4916 | 111 | 동일 과제·safe/poisoned·실제 sink/action trace 기반 agent harness | 완료 | EVAL paired single-turn harness, 실제 Docker local model-contract 회귀. 자유 다중턴 agent 또는 외부모델 품질 결과가 아님. |
| E19 | 4916–4919 | 105,111 | 모델 버전/temperature/seed 조건 통제·사례별 여러 run 실측 | 부분 | metadata와 --runs, seed NOT_REQUESTED 기록. 실제 모델 paired 반복 측정 미실행. |
| E20 | 4874–4876 | 112,113 | revoke/admission/scan 시간 정의별 측정 | 부분 | 각 local helper/trace timing 있음. 동일 boundary·전체 환경 비교 가능한 최종 aggregate 부족. |
| E21 | 4881–4886 | 101–113 | No-defense/hash-only/static/full 4 baseline 비교 | 미완료 | paired no-defense/scanner-policy와 static 결과가 있으나 한 실험의 네 baseline 및 chain admission full 비교 없음. |
| E22 | 4925–4929 | 113 | hot/1만 uniform×95/50/0cache×RPC 정상/지연/장애×p50/p95/p99/error | 부분 | LOAD 18cell 계획 중15 검증,16번째 48!==0 assertion, 최종measurement없음. 성공으로 집계 금지. |
| E23 | 4933 | 001,107 | 1/10/100MB scan throughput | 부분 | OCI100MB native import 수용과개별sourcebudget 테스트. 공통 scan-throughput 행렬의 측정은 아님. |
| E24 | 4934 | 104,107 | dependency10/100/1000 throughput | 미완료 | closure functionality는 있음; dependency-scale measurement 증거 없음. |
| E25 | 4935 | 111 | sandbox scenario1/5/20 throughput | 미완료 | probe2..8 bounds 및 normal/adversarial 실행. 1/5/20 성능 비교 없음. |
| E26 | 4936–4937 | 107,112 | worker concurrency별 queue-age/resource 측정 | 부분 | SQL workers/queue metrics 있음; sweep benchmark 완료 aggregate 없음. |
| E27 | 4941–4944 | 113 | register/PASS/quarantine/revoke gas·confirmation·indexer lag/restart | 부분 | TRUST/reconciler recovery tests/local metrics. 모든 항목을 같은환경에서 측정한 최종 표 부족. |
| E28 | 4952 | 101 | explicit poisoning recall≥90% | 미완료 | 현재 외부 static recall25.98%; 이 값은MCPTox 전체 모델 recall이 아님. |
| E29 | 4953 | 101 | benign metadata FPR≤5% | 미완료 | 독립 실제 benign 분모 없음; synthetic 결과로 대체 불가. |
| E30 | 4954–4955 | 110,113 | synthetic exfil100%/known-revoked unsafe allow0 | 완료 | 고정 authored fixture/native chain/Gateway 회귀 범위; 임의 공격 전체로 일반화하지 않음. |
| E31 | 4956–4959 | 112,113 | local<20ms/remote<500ms/revoke<10s/quickscan<5min p95 | 부분 | 지원 local smoke evidence와 budget 존재. full matrix/실원격 scan표본·최신 aggregate 없음. |
| E32 | 4960 | 113 | E2E demo10/10 | 완료 | Main기록 `0351567` CI 반복 데모 성공. 당시 legacy bounded 흐름이지 새OCI2/실모델에 대한결과아님. |
| E33 | 4976–4985 | 101–113 | commit/dataset/model/prompt/policy/image/chain/hardware/seed/rawaggregate 재현성 | 부분 | 각 report/source provenance 다수 존재. 모든 defense/실험을통일한metadata+rawaggregate묶음 부족, LOAD 실패명시. |
| E34 | 4987 | 101 | 위험원문 노출제한과 hash/결과 검증가능성 | 완료 | REALDATA aggregate-only+datasethash, evidenceMerkle, private original bundle. |

## 20장: 책임·한계·운영 원자 요구사항

| ID | 원문 | FR | 요구사항 | 상태 | 근거 및 남은 조건 |
|---|---|---|---|---|---|
| R01 | 5350–5361 | 113 | 위험별 조기신호·책임자·완화책 운영 등록부 | 부분 | 원문/implementation plan에 한계, no-secret/AI-onlywarn/testvectors 구현. 실제 책임자 승인·주기 검토·alert 연결 운영 증거 없음. |
| R02 | 5365–5374 | 101–113 | 실행경로/난독/remote/validator/host/LLM/blockchain assurance 한계 공개 | 완료 | scanner README, policy fullBehaviorCoverage:false, LOCAL_CONTRACT_TEST/providerQuality 구별. |
| R03 | 5380 | 106,112 | 실제 취약 evidence 비공개 보존 | 완료 | private encrypted evidence API/object-storage 경로; raw bundle 공개 투영 제외 회귀. |
| R04 | 5381–5385 | 113 | maintainer/registry 연락·최소정보·긴급summary·패치협의·법적 범위 runbook | 미완료 | 실제 coordinated disclosure workflow/runbook 증거 확인 못함. 실제 취약점이 없어 연락 수행 자체는 요구하지 않음. |
| R05 | 5389,5392–5393 | 001,107 | synthetic 우선·actual malware 비커밋·샘플출처hash | 완료 | authored fixtures, REALDATA 원문 미저장/hash, 외부 sample host실행 없음. |
| R06 | 5390–5391 | 107,109 | 외부C2 차단·credential없는 isolated cloud account | 부분 | DYN 인터넷차단/secret미마운트. 별도 운영cloud account provisioning/검증 증거 없음. |
| R07 | 5394–5395 | 107 | 학교/대회 규정확인·연구범위 밖 persistence/credential 접근 금지 | 부분 | synthetic scope와 runtime격리 구현. 규정 검토·승인 기록 없음. |
| R08 | 5399 | 106,112 | 온체인 PII/rawprompt/email/path/IP 비저장 | 완료 | digest/status/policy/root 중심 contract; offchain private raw evidence 분리. |
| R09 | 5399 | 106,112 | 낮은entropy 민감값 fingerprint의 salt/HMAC/범주화 | 부분 | 공개 allowlist/category/count와 randomcanaryhash 있음. A10 요구 child-secret HMAC fingerprint 전용 경로는 없음. |
| R10 | 5403–5406 | 113 | policyversion/reason/reportroot/validity 공개 | 완료 | TRUST/control-plane policyhash/root/TTL/reason contract. |
| R11 | 5407–5409 | 113 | fresh rescan/maintainer appeal/validator conflict 표시 | 부분 | TA/appeals 재검사·identity/revocation·mode 회귀 존재. conflict UI완결성은 Frontend감사와 합쳐 판정. |
| R12 | 5411 | 113 | 단일 AI 검증자 영구폐기 금지·재현/quorum | 완료 | POLICY/TRUST single-key independent rescan+2-of-3. 같은기관 세키를 조직독립이라 주장하지 않음. |
| R13 | 5415–5428 | 113 | 과대 안전성·최초/완전탈중앙화 표현 금지, 한정 assurance 사용 | 부분 | README/새정책 출력은 제한 명시. 모든배포홈페이지/제안서 문구 전체재감사 전완료아님. |

## 부록 A: 수용 테스트 — 다른 장과 중복이므로 별도 분모 추가 금지

| 수용 테스트 / 원문 | 매핑 | 상태 | 확인 범위와 남은 조건 |
|---|---|---|---|
| A1 source/lock/surface/static/canary/PASS 전제,5696–5701 | FR001–006/101–113,S01 | 완료 | 지원mail/prepared v1 native fullcycle; 임의 npm 전체 승인아님. |
| A1 VERIFIED→ALLOW→restricted spawn→surface→mail→receipt,5709–5714 | S01,S46,S57 | 부분 | TRUST/DYN native E2E 존재. 최신 Nodev2/OCI2와 receipt모든 필드의 동일E2E는 Main/Frontend최종합산. |
| A2 같은publisher서명된malicious update signatureVALID,5720,5730 | FR003,S55 | 부분 | demo signature/contract test 존재. 외부publisher identity검증 일반화는없음. |
| A2 scopeAI+실canary,5721–5722,5731–5732 | S28,S05,E19 | 부분 | 실제local sinkcanary 탐지. localfallback/contractAI와진짜모델 finding품질 구분; 원문의 PURPOSE_SCOPE_MISMATCH는현 SEMANTIC_BEHAVIOR_MISMATCH로매핑. |
| A2 emergency→2FAIL→REVOKED→2Gateway prespawn block,5733–5735 | S58,S56,E30 | 완료 | TRUST v1native fullcycle및contractquorum. 조직독립/실모델결과 아님. |
| A3 drift mismatch/block/terminate/event/rescan,5741–5753 | FR006,S26,S53 | 부분 | collector+Gateway drift/pagination차단 회귀. notification/periodic/event/freshscan전경로 최신 UI합산 필요. |
| A4 FINANCIAL outage/stalecache failclosed+reason,5759–5766 | S57,E22 | 완료 | v2 admission/fallback/STATUS_UNAVAILABLE 회귀; readiness UP은authorization아님. |
| A4 retryID/cacheblockage표시,5767 | FR112 | 부분 | trace/reason/freshness필드 존재, exactretryID+age end-user표시수용은Frontend감사 필요. |
| A5 revoked offline cache retainsblock,5773–5779 | S57,E30 | 완료 | signed-admission/revoke stickyfailclosed tests; stale가ALLOW복원하지 않음. |
| A6 signature duplicate/domain/contract/deadline/setversion,5783–5787 | S57 | 완료 | `tests/contracts/release-registry-v2.test.ts` 실제localEVM 회귀. |
| A7 PASS/FAIL/ABSTAIN noquorum+timeoutnoPASS,5791–5794 | S58 | 완료 | TRUST contract/validator불일치ABSTAIN회귀. UI표시는R11에서별도부분처리. |
| A8 bytechange→rootmismatch→untrusted,5798–5800 | FR004,S54 | 완료 | ID path-boundMerkle/TA validator재구성 및root mismatch tests. |
| A8 integrity alert,5801 | FR112 | 부분 | fixederror/events·검증거부 존재. 운영자통지전달 실제 alert수용은Main운영감사 필요. |
| A9 traversal/symlink/archivebomb/filecount거부,5805–5808 | FR001,S46 | 완료 | ING archiveactualtar/symlink/size/ratio/filecount회귀; bounded OCI도별도limits. |
| A10 childstderr secretredaction,5812–5813 | R09,FR112 | 부분 | rawstderr공개금지/fixedcategory+knownpatternsredaction. 정확한 `[REDACTED:API_TOKEN]` 전용end-to-end사례는없음. |
| A10 restricted evidence HMACfingerprint,5814 | R09,FR112 | 미완료 | secret-fingerprint용HMAC 구현검색근거없음; S3 SigV4 HMAC나랜덤canary SHA256은대체아님. |

## Coverage notes — 별도 완료 분모를 늘리지 않는 줄

- 1714–1723은 방어 수단별 한계 설명. S01/R02에 반영한다.
- 1730–1765,1802–1810,1829–1854,1894–1917,1934–1949,1973–1975,2014–2028,
  2054–2075는 예시 JSON/토폴로지/Rego다. 문자열·주소·정확한 메모리숫자·OPA제품 도입을 독립기능으로 세지 않는다.
- 1873의 MVP 권장은 전체원문목표에서 해당기능을삭제하는 허가가 아님. Analyzer/Critic/verifier/policy는 S28–S34로 판정한다.
- 1953–1955 gVisor/microVM은 명시적 고려사항/해커톤 비필수. 미구현 사실을 기록하되 필수분모에 자동 포함하지 않는다.
- 2000–2006 eBPF/Falco/gVisor/WASI/fsdiff/profile은 확장 선택지. 기본 관찰부족 S53을 이 목록으로 숨기지 않는다.
- 2079–2086 매트릭스는 S58 하나의 정책 수용조건이며 각각의표셀을독립완료로세지않는다.
- 4805–4813 평가질문은 E02–E08의 실제실험과매핑하며별도중복카운트하지않는다.
- 4888 경쟁scanner 비교는 '가능하면' 옵션. 수행하지않았고기존제품대비우위주장없음.
- 4901–4906은 예상해석/한계이지측정결과가아님.
- 4946–4962는 명시된목표치. E28–E32에서실측범위와미달/미측정을분리했다.
- 4964–4972 결과표template은 E02–E27 실험의표현형식이며새baseline측정증거가아님.
- 5352 stdio/npm1개로범위를줄이라는원문위험완화예시는사용자의전체구현목표를축소하지못한다.
- 5365–5372는 영구적으로남는assurance한계이고, 완전무결한detector를완료조건으로삼지않는다.
- 5378의실제취약점발견은조건부사건. 실제대상공격이나실제maintainer연락을감사를위해실행하지않았다.
- 5415–5428은금지/권장문구예시이며각슬로건을별도제품기능으로세지않는다.
- 부록A는앞선FR/상세요구의수용시나리오다. 동일기능을두번세지않고추가실패조건만원자행에반영한다.

## 우선 남은 작업 — 이번 감사에서 실행하지 않음

1. Main `7bac78a`의 진행 중 Linux결과를확정하고 Nodev2 fullcycle의 실제pass/skip/실패를갱신.
2. 미통합 `8c13b9c` 코드리뷰 및 native OCIv2 gate 검증. 이후에만 별도 API/validator/UI 활성화 계약 진행.
3. 모든LLM전송caller를분류·동일privacy정책으로전환. 원문전체보냄이나default no-op으로요구를대체하지않기.
4. behavior manifest 전계약, multi-turn/shadowing/output-poisoning, 일반언어정적분석·OCI파일행동관찰 격차 해결.
5. 외부모델/독립라벨/benign분모/4baseline/6ablation/부하행렬/실원격운영지표 검증. 목표수치를성과로먼저작성하지않기.
6. disclosure runbook·운영cloud계정·규정검토·stderr secret HMAC evidence 검증.

계정한도조건에따라새구현·원격push·새CI를시작하지않았다. 이파일은read-only감사결과만기록한다.
