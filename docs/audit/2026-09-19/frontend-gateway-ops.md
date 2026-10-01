# 마스터 원문 재감사 — Gateway·관측·개발/데모·발표/도입

기준일: 2026-09-19 KST. 담당: Frontend/Gateway. **신규 기능을 구현하지 않은 읽기전용 감사**이며 이 문서만 추가했다.

## 1. 기준과 집계 규칙

- 원문: C:/Users/박시훈/Downloads/MCPShield_전체_시스템디자인_해커톤_마스터문서.md
- 원문 SHA-256: 702268984174af450276b5292a4afccd6a4d5dce79738fe3abde41c4d30d4ea2.
- 전부 읽은 담당 범위: **2486–2824, 3429–3637, 3776–4793, 4991–5345, 5432–5555, 5818–5877**, 합계 2,105줄. 파일은 마지막 빈 줄 포함 split 기준 5,997줄이며 ReadAllLines는 5,996줄이다. 아래 줄 번호는 원문의 1-based 번호다.
- 코드 열람 기준: Main e55c1ab의 scoped API를 포함한 **7bac78a689b478e2aa6f4e2714a425d5c17a263b**. 마지막 status 확인 때 clean. Frontend f8ea771은 Main 1686547로 통합되어 있다. 본 감사 문서를 담은 별도 frontend 브랜치 HEAD가 Main 기능 기준을 뜻하지 않는다.
- 이번 감사에서 외부 배포, 전체 테스트, 브라우저, Docker, GitHub 설정 변경은 실행하지 않았다. 코드/기존 테스트를 읽고, 직접 수행했던 회귀 및 Main에 남은 커밋별 실행 기록을 대조했다. 과거 CI 결과는 최신 HEAD의 성공으로 전용하지 않는다.
- **완료**: 좁게 명시한 구현 요구에 코드와 실제 실행 증거가 함께 존재한다. 운영 수치·현장 검증을 요구하는 행은 코드만으로 완료로 하지 않았다. **부분**: 작동하는 하위 범위는 있으나 원문 전체 조건/최신 통합/운영 증거가 남는다. **미완료**: 해당 산출물·기능·실행 증거를 찾지 못했다. 미확인은 불가능하다는 뜻이 아니다.
- 각 FG/OB/DV/DM/PT/AD ID는 이 감사의 재사용 가능한 요구 식별자다. **같은 기능을 FR 행, 개발 순서, 주차 계획, Q&A, 체크리스트에서 다시 세지 않는다.** FR 매핑된 기능의 전역 분모 소유자는 해당 FR이다. 부가 운영/제출 요구만 별도 원자로 합친다. 표의 행 수를 그대로 전체 구현률의 분모로 쓰지 않는다.
- 원문 선택안/예시/향후 계획은 coverage에 보존하되 기본 FR 분모와 분리한다. 사용자 전체 목표에 포함된 pilot/production 요구는 Main의 독립 extras 분모에 포함하고, 동일 기능의 기술 대안 각각은 중복 가산하지 않는다. COULD인 FR-407은 우선순위 표시를 유지한다. 목표 수치에 대한 실측/운영증거가 없으면 계획을 완료로 계산하지 않는다.

## 2. 실행 증거 사전

| 증거 | 실제 확인 범위와 한계 |
|---|---|
| E1 — 과거 최신 Linux CI | 원격 0351567, [run 35425746994](https://github.com/sihoon-0077/MCPShield/actions/runs/35425746994). Main 기록상 Node 24·PostgreSQL 성공, 기존 OCI worker→별도 single-key validator→V2→두 Gateway 2 PASS/0 SKIP, prepared npm 3 PASS/0 SKIP, 10회 실제 격리 검사→EVM→Gateway 반복 데모 성공. **전체 실패**: Compose dashboard에 scoped-policy.mjs COPY 누락. 후속 Grafana/일부 audit·secret 단계 skipped. signed-image의 이미지 smoke·취약점·SBOM은 성공했어도 provenance/SBOM 서명·검증·보관은 skipped. |
| E2 — 최신 Main 로컬 | docs/master-implementation-plan.md 최신 체크포인트: e55c1ab 전체 npm test 종료 0, backend+기본 Next build 성공; scoped 회귀 7 PASS. db9e28b UI/BFF/Gateway 집중 16 PASS, native built Next HTTP forms 3 PASS. Docker/PG opt-in skip은 Linux 성공을 대신하지 않는다. 최신 scoped v2의 새 Linux fullcycle는 gate만 추가, 미실행. |
| E3 — 담당자가 직접 실행한 UI/Gateway | frontend 36681da: dashboard 40 PASS/1 조건부 HTTP SKIP, Gateway 110 PASS/2 Linux Docker SKIP, Next webpack production build+typecheck 성공. v1/local-v2/provider-v2 identity·서명 cache 분리와 expiry/revocation 회귀 포함. UI hydration은 미실행. pagination 303870c: 실제 SDK→Gateway→Node child initialize/raw tools page/cursor+SDK 집계 검증 포함 45 PASS. |
| E4 — 담당자가 직접 실행한 최신 오류/재검사 | f8ea771(client/BFF) 8 PASS, dashboard typecheck 성공. arbitrary 한국어/영어/경로/토큰 원문을 알림에 반사하지 않음, machine code/status 유지, 응답 유실시 자동 재전송 없음. Backend 208fa2c read-only 재검사: chainUnavailable 보존, 일반 scan/appeal mode 불일치 409, 잘못된 요청 queue 0건·appeal slot 미소비, 같은 key 올바른 재요청 202. Main e55c1ab/1686547에 통합. |
| E5 — health/telemetry 과거 실행 | Main 기록: SQLite→실제 API→BFF→health CLI·로컬 EVM 장애 focused 8 PASS; PG CI 40 PASS/1 native Docker SKIP에 worker heartbeat 포함. 실제 OTLP HTTP exporter로 scan→validator→chain→indexer→admission 연결 27 spans(전체 88 spans/3 exports/53,741 bytes). 루프백 collector 계약 검사이며 운영 collector·알림 수신·SLO 실측이 아니다. |
| E6 — 측정 파일 | benchmarks/results/mcptox-static-2026-09-09.json: 공격 메타데이터 485 records, static review 126/485=25.98%, FPR/agent ASR null, 모델 NONE. admission-matrix-10000-2026-09-09.json: 10,000 identities setup 완료하나 **PARTIAL_FAILED**, 18 cells 전체 측정 완료 아님. docs/evaluation.md의 10+10 반복 fixture 결과는 2026-09-04 역사적 결과, 외부 일반화 성능 아님. |
| E7 — 배포·산출물 | README의 기존 Railway /try·/mcp는 합성 데이터 데모. Main 기록의 과거 GET 200은 최신 master 배포나 실제 MCP 호출 증거가 아님. 추적 파일 inventory에 pitch HTML+PNG, 기술 설명 HTML, README·Mermaid·runbook 있음. PPT/PPTX/PDF/GIF/MP4·발표 녹화·LICENSE/third-party notices는 추적 파일에서 찾지 못함. 로컬 저장소 밖 개인 파일의 부재까지 단정하지 않는다. |
| E8 — 감사 중 새 CI 부분 관측 | Main이 [7bac78a / run 35427980359](https://github.com/sihoon-0077/MCPShield/actions/runs/35427980359)를 확인: Node 24·PostgreSQL success, Node 22 진행 중 **scoped Node scanner native step 14 failure**, 이후 step 19 진행. 원인 로그/전체 terminal 결과는 이 감사에 없음. 새 scoped-v2 Linux 전체 성공이 아니며 최종 상태는 Main 종합 감사가 갱신한다. |

## 3. Gateway 요구 원자

| ID / 원문 줄 | 요구 / FR 매핑 | 상태 | 코드·테스트·실행 증거 | 남은 범위 |
|---|---|---|---|---|
| FG01 / 2490–2515 | stdio wrapper와 client 접점 / FR-301 | 완료 | apps/gateway/src/index.mjs:320,449; README MCP 설정; scripts/demo/mcp-e2e.mjs; E1/E3 실제 SDK initialize/list/call | 배포 방식 선택안 중 SDK launcher/reverse proxy는 이 완료에 포함하지 않음 |
| FG02 / 2517–2553 | exact bytes 고정→admission→허용한 entrypoint만 spawn / FR-302 | 완료 | artifact.mjs, prepared.mjs, oci-prepared.mjs; index.mjs:109,159; prepared.test.mjs:174; E1 실제 두 Gateway에서 폐기 이미지 create/start 0 | 지원 프로필에 한정, 임의 command/npx 자동실행 아님 |
| FG03 / 2517–2553,2683–2718 | 미검증 후보는 격리 검사, 승인 실행도 제한 / FR-303 | 부분 | prepared/OCI Docker read-only/nonroot/network-none, Node fixture permission model; prepared-docker/oci-prepared-docker tests; E1 | fixture용 host Node 경로와 Docker 경계를 구분해야 함. production Linux runner 운영·kernel escape 검증 아님 |
| FG04 / 2557–2565 | version·tarball/OCI·lockfile·bytes 검증 / FR-001–006 중복 | 부분 | resolver source/closure/binding, Gateway 로컬 snapshot·CID 재확인; E1 | 일반 수집 범위·전체 OCI 보장은 Security 감사 소유. 선택적 Sigstore verifier는 없음 |
| FG05 / 2567–2574 | digest/manifest/surface·활성 policy·expiry·quorum/set·chain/confirmation 일치 / FR-305 | 완료 | signed-admission.mjs:82; contracts-sdk v2-chain-reader; prepared identity; E1/E3 expiry·mode/id tamper·revoked regressions | legacy /api demo는 이 v1 signed assurance가 없으며 완료 범위 밖 |
| FG06 / 2576–2586 | tier·조직/namespace/validator allowlist·host 추가 path/domain 제약 / FR-305 상세 | 부분 | exact policy/set/tenant binding, strict/balanced, 제한 import/network profile; E3 | 세분화된 조직 policy tier/namespace 허용목록·host 제약 병합 엔진은 전부 연결되지 않음 |
| FG07 / 2588–2621 | 전체 tools metadata canonical surface pinning / FR-004–006,304 | 완료 | protocol-guard.mjs:95–118 전체 pages 수집; 원본 tools hash, cursor loop/duplicate rejection; E3 실제 raw cursor protocol | 인증별 동적 tool surface는 FG08, JCS 구현 준수는 DV02로 별도 |
| FG08 / 2588–2621 | auth profile·scope·anonymous 여부별 surface attestation / FR-304 상세·pilot 확장 | 미완료 | 현재 exact 전체 surface와 tenant admission은 있으나 per-auth surface evidence 식별자는 없음 | 원문 MVP 공개 기본 목록과 pilot 사용자별 surface를 구분. 이 확장은 기본 FR 분모에 중복 가산하지 않음 |
| FG09 / 2623–2636 | list_changed 재수집·불일치 신규 호출 차단/child 종료 / FR-304,307 | 완료 | protocol-guard.mjs:165; gateway.test.mjs:77,364; E3 | 선택적 tool output scanner/세밀한 인자 정책은 미포함 |
| FG10 / 2623–2636 | drift 운영 이벤트 전송→긴급 rescan / FR-307,401 | 부분 | index.mjs:344 gateway_runtime_blocked JSON 로그는 있음 | control-plane 이벤트 접수·자동 긴급 재검사 연결 없음, running call complete/cancel 정책 선택도 없음 |
| FG11 / 2638–2651 | READ_PUBLIC/PRIVATE·WRITE_LOCAL/EXTERNAL·DESTRUCTIVE·FINANCIAL 별 scope/확인/fresh check / FR-305 상세 | 부분 | index.mjs:231는 읽기/그 외 2분류; API/UI admission select는 5종; 직접 RPC 고위험 불허 | financial/delete 사용자 확인·scope/path별 강제·6분류 전부 자동판별하는 call policy는 없음 |
| FG12 / 2653–2681 | in-process→persistent→조직 signed indexer→direct RPC / FR-306 | 완료 | signed-admission/admission-fallback.mjs, private file+lock, pinned issuer, bounded multi-RPC; E3+실제 local EVM fallback test | 문서의 SQLite/RocksDB는 대안이며 실제 cache는 파일. direct RPC는 light-client proof 아님 |
| FG13 / 2653–2681 | cache key·TTL·revoked permanent·읽기만 stale / FR-306 | 부분 | tenant/credential/chain/release/policy/set/op bound, <=60s read-only cache, terminal journal; signed-admission.test:151 | 상태별 30s–5m/15–60s negative TTL·event push invalidation의 문서 표 전체와는 다름 |
| FG14 / 2653–2681 | cache 서명·blockhash 검증/변조 거부 / FR-306 | 완료 | signed-admission.test:41,77,115,168,183; fallback direct RPC blockhash 재확인; E3 | 정기 RPC 교차검증 스케줄러는 없음; 필요시 조회 경로와 구분 |
| FG15 / 2683–2718 | RO root/tmp·hostsecret deny·network deny·child/resource 제한 / FR-303 상세 | 부분 | prepared/OCI 고정 Docker argv, snapshot import/permission guard, gateway.test:229,482–611; E1/E3 | 실서비스 허용 domain 프록시·session write path·secret broker 주입은 Gateway에 전부 연결되지 않음 |
| FG16 / 2720–2772 | MCP stdout/framing·ID/schema·frame limit·early call 차단 / FR-309,310 | 완료 | protocol-guard.mjs:37–61; protocol-guard tests, real SDK cursor test; E3 | 지원 tools-only MCP 범위. resources/prompts/sampling/elicitation은 명시적 차단 |
| FG17 / 2720–2772 | stderr 비밀 제거·EOF/TERM→KILL·cleanup / FR-309 | 완료 | index.mjs:125,153; gateway.test:597,611; prepared cleanup ownership regressions; E1/E3 | Windows/macOS 모든 runtime 지원은 아님; descendant는 기본 금지 |
| FG18 / 2774–2793 | remote URL/TLS/origin/auth/metadata drift + REMOTE_METADATA_ONLY 배지 / 추가 remote 요구(FR-310 아님) | 미완료 | index.mjs:388의 /mcp는 자체 합성 stdio tool을 원격 노출하는 서버이지 외부 remote 검증기 아님; 지정 배지 구현 미발견 | 외부 remote 등록·SSRF/Origin/auth 경계·별도 assurance UI·관련 tests 필요 |
| FG19 / 2795–2813 | 차단 시 exact release/reason/status/report·비밀 비노출 / FR-308 | 완료 | index.mjs:24–27, signed-admission.mjs:93,287; control-client와 evidence BFF; E3/E4 | 제한된 프로필/인증 보고서 링크 기준 |
| FG20 / 2795–2813,5546–5548 | evidence destination/policy/마지막 안전 버전·안전대안 선택 UX / FR-308 상세 | 부분 | 콘솔 exact hash/policy/expiry/보고서·재검사·appeal, E2/E4 | 차단 CLI에 마지막 안전 버전 추천/원클릭 rollback·권한 확인된 상세 대안은 없음 |
| FG21 / 2815–2821 | Gateway bypass 경계 공개·production 기본 우회 금지 / FR-301/305 | 부분 | SECURITY.md, Gateway README, MOCK never spawn, run/stdio enforce; E3 | 조직 endpoint management·서명 managed config/process policy 강제는 운영 구축 안 됨 |
| FG22 / 2815–2821,5520 | 짧은 break-glass + 감사 / FR-305 상세 | 완료 | break-glass.mjs: 개인 operator signed <=60s exact read 1회, AES-GCM SQLite 감사; break-glass.test 전체 E3 | public UI/HTTP 불허; 일반 상태/REVOKED를 변경하지 않음. 조직 승인 운영은 별도 |

## 4. 관측·운영 요구 원자

| ID / 원문 줄 | 요구 / FR 매핑 | 상태 | 코드·테스트·실행 증거 | 남은 범위 |
|---|---|---|---|---|
| OB01 / 3431–3451,3535–3557 | API→queue→worker→validator→chain→indexer→admission trace / FR-401 | 완료 | packages/telemetry/index.mjs, control worker/validator/v2 spans, tests/integration/fullcycle-telemetry.test.ts; E5 | 연결된 instrumented stages 기준; 운영 분산기관 증거 아님 |
| OB02 / 3431–3451,3553–3557 | allowlisted bounded attrs·W3C context·고 cardinality label 제한 / FR-401 | 완료 | telemetry/index.mjs:11–18,62–100; telemetry.test/fullcycle-telemetry.test; E5 | caller baggage/tracestate 자동 전파 안 함 |
| OB03 / 3535–3557 | resolve/download/canonical/static/AI/probegen/sandbox 각 하위 단계 상세 span / FR-401 상세 | 부분 | stage enum resolve/static/ai/sandbox/evidence/validator/chain/indexer/admission/scan/http | 다운로드·정규화·probe 생성·normal/adversarial별 세밀한 span 전부가 아님 |
| OB04 / 3506–3533 | 구조화 로그·trace 연결 / FR-401 | 부분 | Gateway JSON log, API trace, durable cp_events, E5 | 모든 프로세스 로그가 제시 JSON 공통 필드로 통일되지는 않음; console diagnostic도 존재 |
| OB05 / 3506–3533 | raw credential/canary/prompt/PII 비노출, private evidence / FR-403 | 완료 | explicit telemetry allowlist, stderr coarse category, encrypted evidence/RBAC; telemetry·BFF·client secret regressions E4/E5 | 완료는 테스트된 경로 한정, 임의 조직 로그/외부 SIEM 전체 감사 아님 |
| OB06 / 3453–3465 | admission availability 99% MVP/99.9% pilot | 미완료 | health/monitor 코드 있음 E5 | 운영 시간창 가용성·error budget·기간 실측 없음 |
| OB07 / 3453–3465 | cached admission p95 <20ms/<10ms | 부분 | scripts/ops/evaluate-admission.ts, cache tests; E6 부분 matrix | 목표를 증명하는 완결/대표 부하 보고서 없음 |
| OB08 / 3453–3465 | remote admission p95 <500ms/<200ms | 부분 | latency histogram/Prometheus 500ms alert, E6 | 외부 RPC/운영망 분포 실측·목표 달성 없음 |
| OB09 / 3453–3465 | revocation propagation p95 <60s/<15s | 부분 | call 재검사/두 Gateway 테스트·local measurement harness E1/E6 | push·idle session 지속 중단 SLA, 5분 이상 운영 p95 실측 없음 |
| OB10 / 3453–3465 | known REVOKED unsafe allow =0 | 부분 | terminal race/outage/cache tests, E1/E3 기능상 거부 | 운영 전체 호출의 0건 불변식 metric·관측 기간/alert 없음 |
| OB11 / 3467–3476 | scan p95 <5m | 부분 | scan stage durations·fixture/CI 실행 E1/E6 | 다양한 실제 패키지 workload의 end-to-end 목표 검증 없음 |
| OB12 / 3467–3476 | queue p95 <2m | 미완료 | SQL nextAttemptAt/createdAt 자료 존재 | queue wait histogram/대표 부하 실측 없음 |
| OB13 / 3467–3476 | sandbox timeout <10% | 부분 | timeout 분류·테스트 E1 | 운영 분모·timeout rate 보고서 없음 |
| OB14 / 3467–3476 | duplicate work <5% | 부분 | queue idempotency/lease/attempt fence 테스트 E1/E4 | 실제 중복 실행률의 관측 기간·분모 없음 |
| OB15 / 3467–3476 | evidence integrity 100% | 부분 | GCM/hash/Merkle 변조 거부 tests E2 | 검증 기능은 있으나 운영 evidence 전체 건수 대비 100% 측정 아님 |
| OB16 / 3478–3484 | 탐지 TPR/FPR·ASR reduction | 부분 | E6 static recall25.98%, 반복 fixture; agent harness 계약 검사 | 실제 provider·benign denominator·독립 labeled population ASR/FPR 남음. Security 소유 중복 |
| OB17 / 3478–3484 | deterministic reproduction rate·mean quarantine·appeal overturn rate | 부분 | 10회 데모 E1, appeal 이력 E4 | 일반 공격/신고 모집단·처리시간/번복 비율 측정 없음 |
| OB18 / 3486–3504 | admission decision/latency·stage duration/error 지표 | 완료 | telemetry/index.mjs:59–63, recordAdmission; official exporter contract E5 | 4종 기본 instrument 구현만 완료 |
| OB19 / 3486–3504 | HTTP 요청·cache hit/miss·queue age 지표 | 부분 | HTTP span·durable queue·cache 로직은 있음 | 제시 신호별 dedicated counter/histogram/Grafana panel 없음 |
| OB20 / 3486–3504 | sandbox active/killed·findings counter | 부분 | scanner 결과·kill/findings trace 있음 | 집계 metric과 운영 collector 패널 없음 |
| OB21 / 3486–3504 | LLM tokens·cost·quota metric | 부분 | provider 예산 제한·결과 metadata는 Security 구현 | 실제 비용/기간별 집계·알림 dashboard 없음 |
| OB22 / 3486–3504 | validator attest·chain tx·indexer lag·revocation propagation metric | 부분 | 단계 span/counter·chain action table | 전용 outcome/lag/propagation signal과 운영 검증 없음 |
| OB23 / 3559–3573 | 운영 dashboard queue/age·capacity·LLM·RPC/indexer·validator | 부분 | operations-console의 inventory/scan/chain/health, deploy/observability/grafana/dashboards/operations.json | Grafana 기본 지연·판정·stage 패널 외 queue/cost/lag/validator 전체 요건 부족 |
| OB24 / 3575–3581 | 보안 dashboard findings/quarantine/revoke·namespace·drift·dest·breakglass | 부분 | evidence-view, status 필터, receipt-console | namespace별 집계·runtime drift/egress destination/breakglass 운영 화면 연결 없음 |
| OB25 / 3583–3587 | demo5cards release/digest·AI diff·timeline·quorum·chain/BLOCK / FR-402 | 완료 | dashboard.tsx:90–154, judge-demo, backend live/replay clients; E1/E2 | 현재 운영 콘솔 전체 hydrated browser QA는 별도 |
| OB26 / 3589–3601 | 9종 alert + 각 runbook + 실제 전달 | 부분 | alerts.yaml는 collector unavailable/admission p95/stage error **3개**; runbook 있음 | 원문 revocation delay, known-revoked allow, escape, equivocation, indexer>20, queue>10m, cost spike, FPR spike, object mismatch 모두 전용 rule/receiver test 필요. Alertmanager 수신자 미구성 |
| OB27 / 3603–3622 | private append-only high-risk receipt·hash chain / FR-407 COULD | 완료 | gateway/receipts.mjs, receipts.test, calls opt-in hook:235; E3 | raw args 미기록, 키/로컬 DB 운영은 별도 |
| OB28 / 3603–3622 | receipt Merkle batch·anchor·inclusion proof / FR-407 COULD | 부분 | receipt-control/relayer, ReceiptAnchor contract/SDK, receipt UI; local EVM confirm/reorg tests | 자동 주기 scheduler와 외부 chain anchor 운영 검증 없음 |
| OB29 / 3624–3634 | propagation 지연 9단계 runbook·긴급 signed denylist | 부분 | operations-runbook 실행허가 장애/reorg 조치·cache journal 보존 | Redis/pubsub 미사용 대체 진단, host heartbeat/적용비율·긴급 denylist 배포·postmortem drill 미완료 |
| OB30 / 원문 상세를 보조 | 종합 health + 단발 monitor (원문의 운영 관측 보강) | 완료 | control-health.ts, health-panel.tsx, scripts/ops/check-control-health.ts, health/BFF/monitor tests E5 | READY≠안전/실행승인. 자동 주기/사람에게 알림 없음. 전역 분모에 신규 목표로 추가하지 않음 |

OB26의 9종 필수 알림은 아래 원자로 구체화한다. OB26 요약과 OB26A–J를 동시에 분모에 넣지 않는다.

| ID / 원문 줄 | 요구 / FR 매핑 | 상태 | 코드·테스트·실행 증거 | 남은 범위 |
|---|---|---|---|---|
| OB26A / 3589–3601 | revocation propagation p95 초과 5분 알림 / OB09 운영 후속 | 미완료 | alerts.yaml에 해당 rule 없음 | metric·threshold·fault injection·runbook 연결 |
| OB26B / 3589–3601 | known-revoked allow >0 즉시 알림 / OB10 운영 후속 | 미완료 | 거부 회귀는 있으나 해당 alert 없음 | 실제 잘못된 허용 탐지 counter와 수신 검증 |
| OB26C / 3589–3601 | sandbox escape signal 알림 / FR-107 운영 후속 | 미완료 | 격리 tests와 구별, 해당 alert 없음 | signal 수집·즉시 대응 runbook/수신 |
| OB26D / 3589–3601 | validator equivocation 알림 / FR-209–211 운영 후속 | 미완료 | chain/governance tests와 구별, 해당 alert 없음 | 충돌서명 관측 rule·수신 검증 |
| OB26E / 3589–3601 | indexer lag >20 blocks 알림 / OB22 | 미완료 | collector availability alert는 block lag 아님 | latest/confirmed head 차이 metric·지속조건 검증 |
| OB26F / 3589–3601 | queue oldest >10분 알림 / OB12 | 미완료 | queue timestamp는 있으나 dedicated alert 없음 | oldest age metric·실제 대기 주입 |
| OB26G / 3589–3601 | LLM 비용 급증 알림 / OB21 | 미완료 | budget 제한이 비용 급증 알림은 아님 | 실제 사용량 집계·baseline·수신 |
| OB26H / 3589–3601 | benign FPR 급증 알림 / OB16 | 미완료 | 실제 benign FPR 운영 분모 없음 | labeled denominator·baseline·rule |
| OB26I / 3589–3601 | object hash mismatch 알림 / FR-403 운영 후속 | 미완료 | 변조 거부 tests는 있으나 alert 없음 | 전용 counter·사건 연결·수신 |
| OB26J / 3589–3601 | 알림별 runbook/운영 Alertmanager 실제 사람에게 전달 | 미완료 | operations-runbook는 수신자 미구성을 명시 | 승인된 수신 경로·secret·복구/중복억제·실제 수신 drill |

## 5. 개발 청사진·CI·검증 요구

| ID / 원문 줄 | 요구 / FR 매핑 | 상태 | 코드·테스트·실행 증거 | 남은 범위 |
|---|---|---|---|---|
| DV01 / 3778–3802 | 최종 stack/혼합언어 계약 | 부분 | npm workspace·Node22/24 TS/Fastify·Next·Solidity/ethers/solc/Ganache·PG16/SQLite·SQL queue·OTel 실제 구현 | pnpm/Python3.12/Redis7·Streams/BullMQ/MinIO/Foundry/Anvil/Tailwind는 원문 선택과 다름. 기능 대체와 문자 그대로 채택을 구분; 대체 이유 ADR 정리 필요 |
| DV02 / 3798,4051–4075 | RFC8785 JCS library, 직접 구현 금지 | 미완료 | services/scanner/src/canonical-json.mjs:3은 직접 recursive serializer(15줄) | 벡터가 통과해도 원문의 library 사용 금지조건 준수 아님. 검증된 라이브러리/공식 vector 전략 필요 |
| DV03 / 4051–4075,4518–4524 | TS/Python canonical bytes/hash vectors(10개 이상·NFC/NFD/BOM/zero-width/number/null/key/large schema) | 부분 | master-scanner.test.mjs:25 등 NFC/NFD 구별/변조/Unicode 검증 | Python 구현·cross-language 같은 vector CI 없음; 10개 named fixture를 갖춘 독립 vector corpus도 미발견 |
| DV04 / 3804–3880,4516–4519 | README·architecture/threat-model·ADR·protocol/finding schemas·sample report·demo fixture | 완료 | README, docs/architecture.md/threat-model.md/adr-001/002, packages/protocol/schemas, scripts/demo/replay.json, demo/fixtures | 파일 존재/내용+관련 E1/E2. 최신 아키텍처 설명은 일부 오래된 MVP 표기가 있어 DV05 참조 |
| DV05 / 3804–3880 | repository layout·SDK·scripts·policy artifacts·docs 정합 | 부분 | 실제 app/service/package/tests/compose 구조와 인수인계 있음 | 제시 tree는 예시이며 경로 일치 불필요. policies의 3 tier bundle, 생성 SDK/schema pipeline, 최종 proposal/video는 별도 행. architecture.md는 v1 중심 갱신 필요 |
| DV06 / 3882–3928 | API/worker/validator/submitter/indexer/Gateway 신뢰경계 | 부분 | API auth/queue, scanner key 없음, 독립 single-key validator CLI, outbox relayer/indexer, host Gateway; E1/E4 | 독립 OS process는 검증했으나 독립 기관/HSM·다른 운영자 boundary 미검증. Backend/Security 중복 |
| DV07 / 3930–3962 | one-command stack + Docker socket 금지/허용된 runner | 부분 | docker-compose.yml/compose.control.yml:63 static-only worker, socket mount 없음; E1 과거 stack | dynamic worker의 제한된 runner daemon 운영 없음; 최신 Compose build 수정 후 Linux 재실행 남음 |
| DV08 / 3964–3996 | config 우선순위·더 엄격한 override·emergency deny | 부분 | exact trust config·terminal revoked·private one-call grant; init-control/env example | default→env→tenant→host→emergency deny의 일관된 병합 체계/서명 bundle 없음 |
| DV09 / 3964–3996,4185–4193 | secrets/validator key 분리·repo no secret | 부분 | gitignore, secret CI, generated private config, validator independent process | 운영 secret manager/HSM·branch protection·모든 새 HEAD secret gate 미검증; public demo keys는 synthetic으로 명시 |
| DV10 / 3998–4005 | migration version·재구축·backup/rolling schema | 부분 | numbered SQL migrations, reorg projection rebuild, operations-runbook, E1 PG 빈 DB restore drill | 운영 PITR/RPO/RTO·암호화 evidence+key 동시 복구·rolling upgrade drill 미완료. Backend 소유 중복 |
| DV11 / 4007–4017 | schema first·TS/Pydantic/OpenAPI/eventvalidator 생성·additionalProperties false·v1/v2 | 부분 | 고정 JSON schemas/Ajv·v1/v2 type·runtime validation | TS 타입 수동/Python없음, 자동 OpenAPI/Pydantic/schema compatibility generation pipeline 없음 |
| DV12 / 4019–4049 | plugin timeout/memory/outputschema·실패 격리 | 부분 | bounded AI/Docker pipeline·JSON output checks·fallback ABSTAIN tests | 제시 Python plugin interface는 예시이나 범용 plugin별 자원제어/격리 프레임은 없음. Security 소유 중복 |
| DV13 / 4077–4109 | contract interface/events·EIP712/registry/unit/fuzz·local/testnet/ABI/explorer | 부분 | Solidity/SDK·unit tests E1/E2; 1 vote 미승인/2 PASS/terminal revoke 테스트 있음 | Foundry fuzz/invariant campaign·Base Sepolia 배포/source verification/explorer 미완료. Backend 소유로 한 번만 집계 |
| DV14 / 4111–4123 | PR typecheck/unit/schema/canonical/contract smoke | 부분 | .github/workflows/frontend-gateway-devops.yml:47; E1/E2 | lint 전용 command, schema backward-compat diff, contract fuzz 없음; TS/Python vectors는 DV03 |
| DV15 / 4111–4123 | PR container·secret·license scan | 부분 | pinned Trivy builder/image scan, tracked secret regex, dependency license inventory workflow | 최신 verify 선행실패로 일부 skipped; license inventory≠승인 allow/deny 정책 |
| DV16 / 4125–4132 | main immutable image·SBOM·provenance/signature·test deploy·E2E | 부분 | signed-image job/config, CI stack/smoke, E1/E8 | 새 run scoped scanner native 실패 관측; 현재 audit HEAD 전체 gate·서명/검증/보관 성공 없음; 새 공개 배포 없음 |
| DV17 / 4134–4141 | release tag·changelog·signed artifacts·address/config manifest·migration/rollback plan | 부분 | operations-runbook migration/rollback, deploy scripts; 과거 signed artifact 기록 | 최신 release tag/changelog/versioned release bundle 및 실제 rollback drill 미발견 |
| DV18 / 4143–4167 | unit6종·integration5종·E2E4종 | 부분 | hash/rule/policy/state/cache/framing; API DB/outbox/objectstore/validator/evidence/contract/indexer/Gateway tests. safe/malicious/RPC-outage/drift E1/E3 | 최신 전체 native 통과 남음, objectstore는 실제 SDK→loopback 계약검사로 cloud 운영 아님 |
| DV19 / 4169–4181 | archive bomb·symlink·traversal·malformed schema·bidi/zero-width·prompt injection·infinite child·fork/DNS·conflicting votes·reorg | 부분 | master-scanner.test:76, scanner timeout/cleanup, Docker cgroup/network tests, protocol tests, V2 dissent/reorg tests | 실제 fork-bomb/DNS-tunneling 전용 named adversarial test·cross-language Unicode corpus 미발견. network-none/cgroup 존재만으로 해당 공격 실험 완료라 하지 않음 |
| DV20 / 4183–4193 | 안전개발 규칙: host install 금지·script default off·local malicious fixture·dummy data·disclosure·lock/digest·review·key/redaction | 부분 | SECURITY.md/CONTRIBUTING·lockfiles·Docker image pins·source closure script deny·E1/E3/E5 | 기술 제한은 구현. GitHub branch protection/최소1인 강제 review 설정·신고 실제 연락처는 미확인/부재 |
| DV21 / 4195–4231 | P0/P1/P2 우선순위·금지 scope | 부분 | P0 핵심 E1, P1 diff/timeline/2Gateway/benchmark/replay 있음, P2 appeal/cache/receipt 구현 | SBOM viewer·OPA 없고 선택 항목. token/DAO/marketplace/10ecosystem/완전OS·remote·자체모델은 비목표로 유지; 미완료 기능 분모로 추가하지 않음 |
| DV22 / 4535–4539 | benign/attack 30건 unit corpus / FR-101–106 평가 자료 중복 | 부분 | benchmarks/metadata-corpus.json의 cases는 **16개**. E6 외부 MCPTox는 공격 tool records485개지만 benign 분모 없음 | 30개의 구분된 benign/attack unit corpus exit 충족은 아직 아님. 다른 fixture 묶음을 합산하려면 중복/label/provenance부터 확인 |

## 6. 데모·팀·반복 재현 산출물

| ID / 원문 줄 | 요구 / FR 매핑 | 상태 | 코드·테스트·실행 증거 | 남은 범위 |
|---|---|---|---|---|
| DM01 / 4237–4287,4440–4443 | safe/malicious 동일 namespace fixture, synthetic local canary·publisher signature valid | 부분 | demo/fixtures/mail-mcp-1.0.0/1.0.1, scanner tests, SECURITY.md; E1 canary 및 validator 서명 | **publisher 실제 서명은 없음(DM16)**. 원문 send_email/file/domain 이름은 예시; 실제 합성 mail fixture임. 실제 메일 서비스를 뜻하지 않음 |
| DM02 / 4289–4344,4440–4447 | compare/timeline/quorum/chain·두 Gateway pre-spawn·safe 계속허용 / FR-402,302,307 | 완료 | dashboard/judge+E1 실제 two-process Gateway·E3 protocol; live/replay와 ledger 구별 | UI 그림만으로 chain proof라 하지 않음. 최신 scoped v2 native는 E2 한계 |
| DM03 / 4346–4390 | 3분 시연 영상 (safe→malicious→evidence→chain→두Agent→rollback) | 미완료 | scripts/runbook/pitch storyboard는 있으나 추적 영상 없음 E7 | 녹화·실제 실행 provenance·3분 길이 확인 필요 |
| DM04 / 4392–4407,4647 | 8분 deck 및 7분30초 rehearsal | 부분 | pitch HTML 표지+10장 E7 | 8분 발표 대본·7분30초 실측 녹화/리허설 기록 없음 |
| DM05 / 4409–4436 | deploy/reset/safe/scan/revoke/twoGateway 단축 runbook | 부분 | scripts/demo/README.md, package.json demo:*·stack:up, operations-runbook | 실행가능 script 있음. 발표 머신의 terminal·login·local sink·선택 chain 고정 preflight 체크 미실행 |
| DM06 / 4449–4472 | RPC/LLM/sandbox replay fallback·hash 확인·비실시간 명시 | 부분 | replay JSON identity hash 검증·source label, CLI replay/AI failure tests, Dashboard notices | signed evidence bundle replay라고 표기/검증하는 완전 경로와 실제 timeout 리허설·explorer clip는 없음 |
| DM07 / 4451–4472,4498,5851 | 60초 fallback 및 60–90초 영상/GIF local 보관 | 미완료 | README Mermaid·web demo는 있으나 GIF/video 추적 산출물 없음 E7 | 녹화/오프라인 재생 확인 |
| DM08 / 4474–4483 | synthetic-only·외부 공격자/실제key 금지·AI점수단독폐기 금지·과장금지 | 완료 | fixtures/SECURITY/AI policy·public /try fixed target·LOCAL_DEMO 안내, E1–E4 | 시연자 실제 발언/외부 운영 행동까지 검사한 것은 아님 |
| DM09 / 4489–4501 | 최소 PoC 7항목 | 부분 | description diff/hash/canary/contract/CLI/README/Mermaid E1/E7 | 7번째 README 도식 있음; 영상/GIF는 DM07. 선택가점이라는 제출 요건은 기능 분모와 분리 |
| DM10 / 4503–4647 | 주차별 named artifact/exit criteria | 부분 | 아래 coverage 표에 주별 산출물별 연결 | roadmap 문서 존재를 7주 실적 완료로 세지 않음 |
| DM11 / 4645–4646 | clean machine README 재현·10회 연속 실제 demo | 부분 | E1 새 CI runner 실제 10회 성공; 원본 demo reset 스크립트 | 최신 HEAD와 발표 노트북의 clean 재현 미검증; 과거 replay10회만으로 대체하지 않음 |
| DM12 / 4649–4674 | 현장 network/mentor/freeze·address/benchmark 고정·checksum·권한·operator 동기화 | 미완료 | 계획만 있음 | 실제 행사 체크 기록·제출 산출물 checksum·리허설 필요 |
| DM13 / 4676–4733 | 3인/4인 역할·RACI | 부분 | WORKTREE_COLLABORATION_RULES.md 소유영역/Main/Reviewer, 현재 병렬 교차검토 기록 | 실제 참가자 이름·4인 Product 역할·발표/Q&A 책임자 지정 없음; RACI표는 예시 |
| DM14 / 4735–4746 | DoD8종 acceptance/error/metric/secret/doc/review/demo/rollback | 부분 | 테스트/문서/교차리뷰/trace 다수; E1–E5 | 각 기능별 8조건 ledger 미완성, 최신 native/운영 rollback·측정조건 남음 |
| DM15 / 4748–4790 | mentor질문·board/issue8필드·Later관리 | 부분 | master plan/handoff/worktree 규칙과 질문은 원문에 있음 | 실제 프로젝트 board·issue value/threat/acceptance/owner/estimate/observability/security/demo relevance 채움·mentor 답변 기록 미확인 |
| DM16 / 4260–4265,4354,4364,4441 | 같은 publisher demo key로 두 버전을 실제 서명·유효성 확인 | 미완료 | 두 fixture manifest에 서명 없음. resolver.mjs:119/140 publisherEvidence는 빈 배열/verified:false. apps/dashboard/app/api/live/route.ts:43은 signature: UNKNOWN; MOCK demo-data.ts:14–15와 replay.json:30/39만 VALID 고정값 | 실제 publisher signing/verification fixture·변조/다른키 거부 테스트·LIVE evidence 연결 필요. EIP-712 validator 서명·admission Ed25519 서명은 publisher 출처 서명의 대체가 아님. DM01 요약과 이 원자를 중복 집계하지 않음 |

## 7. 제출 PPT·공개 전·발표 체크

| ID / 원문 줄 | 요구 / FR 매핑 | 상태 | 코드·테스트·실행 증거 | 남은 범위 |
|---|---|---|---|---|
| PT01 / 4991–5012,5868 | 표지 제외 10page 기획제안서 | 부분 | docs/pitch/MCPShield_사업계획서_10p.html:967–1251에 표지1+본문10 section | HTML은 편집본. 최종 PPT/PDF 실제 파일·출력 page count와 동일하지 않음 |
| PT02 / 5014–5246,5869 | 필수 주제/항목1–8·AI/chain정당성·기술/평가/계획/팀/출처 | 부분 | 개요·문제·workflow·차별성·solution·prototype·stack·whychain·plan·team 실제 HTML | 최신 성능/범위 반영, ERC-8257 Draft 비교/AI평가·proof 근거 보강, 안내문8항목 최종 대조 필요 |
| PT03 / 5008–5010,5231–5246 | team identity·GitHub·demo QR·6–8핵심출처/full bibliography QR | 부분 | HTML:975,1232–1234 팀명/이름/GitHub 입력란, public demo link와 일부 sources | 실제 이름·소속·공개 repo 링크·동작 QR·90초영상 링크 및 참고 전체목록 완성 필요 |
| PT04 / 5248–5257 | 상태색·읽기쉬운18pt/표6열이하·한메시지/AIchain구별 | 부분 | 흰 배경과 상태색·도식·4열 표·생성이미지 있음 | HTML에 13px 설명/작은 source text 있음(1116), 실제 PPT18pt/print clipping/readability 미검증. 사용자 흰 배경 요구는 원문의 혼합배경 예시보다 우선 |
| PT05 / 5526–5540,5859–5862 | 목표/측정 분리·한계·ERC Draft·과장 제거 | 부분 | HTML:1144 테스트넷 목표, localhost ledger 표기·왜 chain 설명 | HTML:1243–1245 역사적74/74·0취약점 현재성 갱신; provider/독립기관 미검증 경계 더 명확히; ERC Draft 표시 미발견 |
| PT06 / 5856,5870 | 실제 PPT와 PDF 생성·둘다 열기·PDF page count | 미완료 | HTML PDF인쇄 버튼은 존재(1258)하나 E7 파일 없음 | PPT/PDF export·열기·11장(표지+10) 실측 필요 |
| PT07 / 5822–5824 | repo 공개 전 .env/key/RPCtoken 제거·secret scan·fixture 외부endpoint 점검 | 부분 | gitignore/CI secret regex·synthetic sink·E1 과거 성공/실패 경계 | 최신 HEAD 전체 secret gate 및 git history 공개전 점검을 이번 감사에 실행하지 않음 |
| PT08 / 5825 | LICENSE + third-party notices | 미완료 | 추적 파일 inventory에 둘다 없음 E7 | 프로젝트 공개 license 선택·의존성 notices 작성(Trivy license 목록은 대체 아님) |
| PT09 / 5826 | SECURITY.md 신고 이메일/범위 | 부분 | SECURITY.md Supported scope·responsible disclosure 존재 | 실제 비공개 신고 이메일/접수 URL 없음 |
| PT10 / 5827–5829 | README문제/해결/90초GIF·GitHub Mermaid 렌더·one-command | 부분 | README 문제/solution/Mermaid·demo:smoke/stack:up E1/E7 | GIF 없음, GitHub 렌더 결과 이번 감사 미확인; 새 HEAD clean stack 미검증 |
| PT11 / 5831–5839 | chainid/address/tx·sourceverification·validatoraddr·admin한계·EIP712sample·explorer | 부분 | contract deploy/SDK/tests·docs onchain boundary, local EVM E1 | Base Sepolia 주소/배포tx/source verified explorer 증빙 없음. Backend 감사 소유 중복 |
| PT12 / 5841–5852 | demo machine Dockerdisk·runtimepin·font/zoom/terminal·알림off·16:9·hotspot·HDMI | 미완료 | Node engine 범위·lockfile는 있음; 현장 hardware 기록 없음 | 발표용 장비 실측 checklist; Anvil대신local Ganache 선택 설명·fallback 영상은 DM07 |
| PT13 / 5857–5858,5871 | QR 접근·public/심사권한·incognito 링크시험 | 부분 | public URL·GitHub repo 참조 E7 | 모든 제출 링크/QR를 로그아웃 시크릿으로 점검한 기록 없음 |
| PT14 / 5863–5864 | 7분30초 rehearsal·Q&A 담당자 | 미완료 | 역할 초안·30Q 원문 있음 | 실제 타이밍 기록/담당 배정 필요(DM04와 중복 집계 금지) |
| PT15 / 5872–5874 | 파일명규칙·제출완료화면·checksum/backup | 미완료 | 제출 최종 artifact/영수증 추적 자료 없음 | 사용자 제출확인·규칙검증·checksum/보관 필요. 자동 제출 권한을 추론하지 않음 |

## 8. 도입·사업 모델 요구

| ID / 원문 줄 | 요구 / FR 매핑 | 상태 | 코드·테스트·실행 증거 | 남은 범위 |
|---|---|---|---|---|
| AD01 / 5263–5279 | 개발자 CLI·기업 SDK·Registry badge/API·독립 validator 도입 | 부분 | Gateway CLI/API·tenant policy·validator CLI 있음 E1 | packaged public CLI 배포/기업 강제 SDK·SIEM/EDR, scope/policy/expiry badge embedding, 실제 community/독립기관 참여 없음 |
| AD02 / 5281–5312 | 오픈소스/유료경계와 과장없는 가치제안 | 부분 | README/pitch 역할 설명·공개 코드 | LICENSE 없음; 요금/고객/SLA 실증 없음. 유료 가능영역은 사업 선택안이지 구매/매출 목표로 중복 집계하지 않음 |
| AD03 / 5314–5328 | Observe→Warn→Enforce 단계적 rollout | 부분 | index.mjs:220 inspect는 RECORD_ONLY/REVIEW_REQUIRED, run/stdio 항상 enforce; gateway.test:68 E3 | 실제 MCP 운영에서 observe-only inventory·warn 사용자승인·조직 rollout 제어 없음; inspect dry-run과 구분 |
| AD04 / 5330–5338 | 미검증/태그감소·review시간·revoke host비율·bypass·MTTC·중복scan절감 측정 | 미완료 | identity/cache/scan 재사용은 구현되어 있음 | 도입 전후 baseline/tenant host inventory·모든 7지표의 운영 측정 없음 |
| AD05 / 5340–5342 | 네트워크 효과 전제: 다양성·policy표준·appeal·악성신고 방지 | 부분 | policyhash/appeal/RBAC/quorum 구조 E1/E4 | 서로 다른 운영기관·실사용자·신고남용/평가 운영증거 없음; 네트워크 효과 달성 주장 불가 |

## 9. 범위 전체 coverage — 반복·예시·선택안 누락 방지

### 9.1 절별 연결

| 원문 범위 | coverage / 집계 처리 |
|---|---|
| 2486–2515 | Gateway 목적·우회 경계 FG01/21. wrapper/SDKlauncher/reverseproxy는 선택 방식이며 전부 만들라는 3개 필수 요구로 세지 않음 |
| 2517–2553 | 실행 순서 FG02/05/07/16. deny와 제한 spawn을 한 검증 pipeline로 연결 |
| 2555–2621 | hash/attestation/hostpolicy/surface FG04–08. Unicode NFC 권고와 JCS 원문보존은 구분: 현재 NFC/NFD bytes를 합치지 않음. 원문표현 상충은 명시적 ADR 필요 |
| 2623–2681 | drift/action/cache FG09–14. outputscan/argpolicy는 선택확장, LRU/SQLite/RocksDB는 구현대안. periodic RPC는 미구현으로 남김 |
| 2683–2772 | 최소권한·YAML values·stdio pseudo code FG15–17. 샘플 함수명/리소스숫자 그대로의 구현은 요구하지 않되 경계 자체는 검증 |
| 2774–2793 | remote MVP FG18 미완료. pilot reproducible deploy/signedOCI/TEE/workloadidentity/egress/responsemonitor/ownerSBOM은 **미구현 미래 확장**, 기본 FR과 분리해 Main 전체 목표 extras에 포함(의도적으로 누락하지 않음) |
| 2795–2824 | 차단 UX·증거권한·한계/breakglass FG19–22. 원문 예시 침해 상세를 공개 UI에 원문 반사하지 않는 경계 유지 |
| 3429–3451 | OTel propagation/attr OB01/02 |
| 3453–3484 | SLO·성능/탐지목표 OB06–17. MVP와 pilot target을 별도 수치로 보존하되 두 구현기능으로 중복하지 않음 |
| 3486–3504 | metric 이름은 예시, 실제 관측 신호별 OB18–22 |
| 3506–3557 | log예시/금지내용/fullscantrace OB01–05. 샘플 trace JSON의 값 자체는 테스트fixture 요구 아님 |
| 3559–3637 | 운영/보안/데모dashboard·9alerts·receipt·지연runbook OB23–29. 마지막 요약/구분선 포함 읽음 |
| 3776–4075 | stack·tree·module boundary·compose/config·migration/schema/plugin/canonical DV01–12. Terraform/K8s/Turbo/OPA/gVisor는 선택/차기 산출물로 구현 없음, 필수 분모에 억지 추가 안 함 |
| 4077–4233 | contract/CI/pyramid/security/priority DV13–21. 세 Solidity snippet는 1PASS미승인/2PASS/terminal 세 검증의 예시로 tests에 연결 |
| 4235–4485 | demo fixture/UI/timebox/runbook/fallback/금지사항 DM01–08. signature/AI/sandbox/chain/두Agent 구분을 반복 기능으로 새 집계하지 않음 |
| 4487–4501 | 신청 전PoC DM09. 영상/GIF와 공개 README는 별도 named deliverable로 빠짐없이 기록 |
| 4503–4647 | 7주별 상세는 아래9.2. 계획의 경과기간=구현완료 아님 |
| 4649–4793 | onsite/team/RACI/DoD/mentor/projectboard DM12–15. 3인/4인 팀은 대안, 둘다인력충원 요구 아님 |
| 4991–5259 | 10p편집안 PT01–06, 아래9.3. 정확한 페이지 편집순서는 제안이며 기존 사용자 workflow3가지/흰배경 요청이 우선 |
| 5261–5345 | 사용자/가치/무료유료/rollout/7효과지표/network AD01–05 |
| 5432–5555 | Q1–Q30 아래9.4. 반복 FR와 한계설명은 새분모에 추가하지 않음 |
| 5818–5877 | B1 PT07–10; B2 PT11; B3 PT12/DM07; B4 PT05/06/13/14; B5 PT01/02/06/13/15. 체크박스 계획을 실행 증거로 읽지 않음 |

### 9.2 7주 계획에 등장하는 named artifacts와 exit criteria

| 주차 / 원문 | 산출물/exit → 감사 ID / 중복 FR |
|---|---|
| W1 / 4505–4524 | threat-model.md·schema·ADR·safe/malicious 초안 존재(DV04); vectors10개·TS/Python 일치 부분(DV03); 팀 한문장 합의 실제 서명/회의기록 미확인(DM13). Behavior Manifest/identity는 FR-004–006 소유 |
| W2 / 4526–4544 | resolver/versiondiff/OWASP rules/AI JSON·finding schema·sample report 존재(DV04, Security FR-001–106); benign/attack **30건 corpus**는 현재 metadata-corpus16건으로 부족(DV22), 실제 외부30패키지라고 세지 않음. 변화highlight/parsefailure fail-safe는 tests 있음. 모델 품질은 OB16 |
| W3 / 4546–4564 | disposable runtime/FSnetwork/localsink/quota·eventtrace/canaryfactory/critical finding은 FR-107–112; 실제 fixturecanary/cleanup E1. 일반공격100%가 아니라 고정 fixture exit만. DM01/FG03/15/17 |
| W4 / 4566–4584 | ReleaseRegistry/EIP712/quorum/state/ABI 있음; Foundry tests 대체 Node EVM, Base Sepolia deployment/explorer 없음(DV13/PT11). replay/duplicate/stale validator는 기존 FR-201–212 tests에 한 번만 연결 |
| W5 / 4586–4604 | stdio CLI·surface·projection·cache·allow/block·eventstream FG01–17, FR-301–307. terminal/pre-spawn/drift 실제 테스트 E1/E3 |
| W6 / 4606–4625 | compare/timeline/quorum UI OB25, MCPTox/benign 평가 OB16, load/latency/gas OB07–09/E6, 결과표 있음, Grafana기본 OB23. **3분영상draft 없음**(DM03), sample size는 E6에 있으나 전체quality완료 아님 |
| W7 / 4627–4647 | fallback/review/docs/runbook/repro guide DM05/06/14; **30Q&A는 원문에만**(PT14), release candidate/tag DV17, **8분deck** DM04, clean laptop/10회 DM11, 7분30초리허설 없음 |

### 9.3 10페이지 편집안의 콘텐츠 대응

| 원문 | 현재 pitch HTML 및 남음 |
|---|---|
| 4995–5012 표지 | HTML967–979. 이름/소속 입력 필요, demo/repo/영상QR 미완성 PT03 |
| 5014–5040 개요 | HTML981–1012와1035–1051. 업무3종/실행통제 직관적 flow, original exactdigest전체단계를 일부 다른장에 분산 |
| 5041–5062 문제 | HTML1014–1033. signed update/공식 Registry 경계 설명. 사건근거는 원문별 실제 최신 출처검증을 이번 코드감사에서 다시 하지 않음 |
| 5064–5082 차별 | HTML1053–1072. 4열 비교로 단순화. ERC-8257 Draft와 구체적행별 근거는 최종검토 필요 |
| 5083–5102 서비스 | HTML1074–1096/1098–1135. LOCAL_DEMO 명시, 전체status/quarantine/expiry semantics는 console에 존재하나 deck에 전부설명 없음 |
| 5104–5125 스택 | HTML1137–1152. 실제Node구현 표시. 전체원문 JCS/SBOM/근거범위/AI생성평가는 더 자세한 개발문서로 연결 필요 |
| 5127–5154 blockchain | HTML1155–1178. 왜중앙DB아닌지있음. quarantine24h/terminal/chainraw비공개/정책만료 설명은 deck축약에 빠짐 |
| 5156–5179 AI융합 | HTML1041/1080/1143/1161 등 분산. dedicated5role/AI-onlyWARN/recallFPRASR 한장 없음. 호출모드≠품질 입증으로 갱신 필요 |
| 5181–5202 architecture/demo | HTML1038–1044/1078–1092/1108–1129. 3plane/두버전 flow 있음 |
| 5204–5227 plan/metric/evidence | HTML1180–1224. 7주plan 있음, 숫자목표/현재실측/테스트넷·영상증빙은 미완료 분리 필요 |
| 5229–5246 team/impact/ref | HTML1226–1251+1067–1069. team입력란·publicrepo입력란·오래된수치·sources3개. PT03/05 |
| 5248–5257 design | whitebackground/상태색/이미지 적용. 현재화면/PDF 실제읽기검사 및18pt 미달 작은문구는 PT04 |

### 9.4 Q&A 30개를 기능으로 과대 집계하지 않기

| Q / 원문 | 답변의 구현 근거·남음 |
|---|---|
| Q1 / 5434–5436 | 전체 pipeline E1 있으나 제품 완료가 아님; DM01/02. 정상 publisher 서명된 악성 업데이트의 실제 시연은 DM16 미완료 |
| Q2 / 5438–5440 | chain정당성 pitch 존재. 실제 다기관은 AD05 미검증 |
| Q3 / 5442–5444 | signature≠behavior 설명은 있으나 실제 publisher 서명 검증은 DM16 미완료; optional Sigstore integration 없음 FG04 |
| Q4 / 5446–5448 | ERC비교 설명계획, PT02/05; Draft명시 갱신 필요 |
| Q5 / 5450–5452 | chain은claim/evidenceroot; validator local재검사 E1, 독립기관 아님 DV06 |
| Q6 / 5454–5456 | AI-only 영구폐기금지 FR-113(소유Security/Backend), DM08 |
| Q7 / 5458–5460 | sandboxevasion한계·expiry/leastprivilege FG03/05/15; 완전탐지 아님 |
| Q8 / 5462–5464 | quorum/governance FR-205–212, 기관다양성/appeal운영 AD05 |
| Q9 / 5466–5468 | <=24h/criticalquarantine FR-207, DV13/PT11 |
| Q10 / 5470–5472 | 피해복구 불가, 후속call차단 FG09; idle세션 SLA미측정 OB09 |
| Q11 / 5474–5476 | remote별도assurance **FG18 미구현**, 자체/mcp공개를 이를대신하지않음 |
| Q12 / 5478–5480 | bypass및hostadmin한계 공개 FG21, 기업endpoint enforcement미구현 |
| Q13 / 5482–5484 | strict/balanced/readcache/REVOKED유지 FG12–14/E3 |
| Q14 / 5486–5488 | localcache 있음, eventinvalid push없음 FG13; 현재매call freshcheck로안전우선 |
| Q15 / 5490–5492 | actualsink/FS/network/canary FR-107–112, DM01 |
| Q16 / 5494–5496 | metadata semantic/agent harness FR-105–112, OB16 실제provider미측정 |
| Q17 / 5498–5500 | size/file/budget·ABSTAIN/securitycodes E2/E4; generalquick/deeptier는Security감사 |
| Q18 / 5502–5504 | 외부scannerinput확장 선택계획, 실제Snyk/mcp-scan connector 미발견; 새필수분모아님 |
| Q19 / 5506–5508 | localreceipt/Merkleanchor OB27/28; 자동주기anchor·실chain배포없음 |
| Q20 / 5510–5512 | encryptedobjectstore/RBAC FR-403; cloudACL/KMS운영은미검증 DV10 |
| Q21 / 5514–5516 | exactpolicy/mode재검증 E4, terminal기록불변 FG05/20 |
| Q22 / 5518–5520 | exactbytes비용 설명; breakglass FG22 있음. trustedpublisher priorityquickscan scheduler는미구현 |
| Q23 / 5522–5524 | token/slashing의도적비목표 DV21(구현분모제외) |
| Q24 / 5526–5528 | chain필요성과single-companyDB가능성 pitch있음 PT02; chain없는edition은가능성표현이지신규필수요구아님 |
| Q25 / 5530–5532 | AI한정역할 FR-105–113; 실제provider품질 OB16 |
| Q26 / 5534–5536 | 조건/sample/commit표시 E6 있음, fullrecall/FPR/ASR미완료 OB16/PT05 |
| Q27 / 5538–5540 | EVMadapter있음, BaseSepolia배포아님 PT11 |
| Q28 / 5542–5544 | evidenceRoot/Merkleproof FR-202/403, 변조tests E2; OB15운영100%별도 |
| Q29 / 5546–5548 | currentversion/digest/reason/policy/expiry FG19/20. lastsafe대안부족 |
| Q30 / 5550–5555 | 제품한문장/연결demoproof DM01/02. 수상여부나모든실운영보장은검증대상아님 |

## 10. 우선적으로 남은 일 — 구현 요청이 아닌 감사 결과

1. **운영/발표 주장 수정**: 공개 Railway는 원본 synthetic demo, 최신 master는 미배포. provider policy mode를 실제모델 호출/품질로 읽지 말 것. pitch의 오래된 수치/팀 placeholder/독립기관 표현을 최신 증거와 맞출 것.
2. **원문 대비 명확한 기능 gap**: 실제 publisher 서명된 두 버전 fixture(validator 서명과 구별), 외부 remote assurance, 세분화 action/승인·secret broker, drift→자동 rescan, enterprise managed enforcement, 세분화 ops metrics/원문9alerts/수신 테스트, JCS library+TS/Python vector 계약.
3. **최신 검증 gap**: b9f591a Docker closure 수정 및 scoped-v2 새 pipeline의 Linux native/full Compose 후속 run. 새 7bac78a run은 Node24/PG 성공이지만 scoped scanner native 실패 관측(E8); 전체 결과/원인은 Main에서 확정. 이전 run의 다른 성공 stage를 새 코드 전체 성공으로 합산하지 말 것.
4. **별도 산출물 gap**: LICENSE/notices·SECURITY 신고주소, 실제 PPT/PDF·90초/GIF·3분/60초 fallback 영상, 7분30초 리허설, QR/시크릿 접근·제출완료/체크섬. HTML 존재만으로 대신 완료처리하지 말 것.

이 부분 감사에서는 전체 구현 퍼센트를 산출하지 않는다. Main이 FR·비기능/운영·선택확장·제출 산출물을 각각 중복 제거한 분모로 합산한 뒤, 부분의 가중치를 명시해야 한다.

## 11. Main canonical FR50 표에 대한 권고 (이 표는 중복 집계 금지)

원문의 정확한 FR 문구(554–575줄)를 기준으로 core와 상세 확장을 분리한다. 지원되는 stdio 프로필의 core 완료가 외부 remote/기업 운영 전체 완료는 아니다.

| FR / 원문 줄 | 권고 | 근거 / 남음 |
|---|---|---|
| FR-301 / 554 | 완료 | FG01. 실제 SDK가 gateway command를 통해 연결, demo config/CLI 있음 |
| FR-302 / 555 | 완료 | FG02. exact local identity와 pre-spawn check, E1의 두 Gateway create/start 0 증거. 신규 scoped-v2 Linux 전체 통과는 별도 E8 미달 |
| FR-303 / 556 | 부분 | FG03/15. prepared/OCI Docker 실제 격리 있으나 host fixture runner와 운영 Linux runner/지원 profile 차이를 남김 |
| FR-304 / 557 | 완료 | FG07/09. 전체 page hash·drift 차단·실제 child 종료 E3. auth-specific future extension은 FG08 |
| FR-305 / 558 | 완료 | FG05. signed v1/V2 exact identity/policy/expiry/status tests. legacy demo assurance와 비공개 explicit break-glass는 분리 |
| FR-306 / 559 | 완료 | FG12/14. strict/balanced·signed read TTL·outage·terminal revocation 실제 local EVM E3. 상태별 TTL 표/운영 SLO는 extras |
| FR-307 / 560 | 부분 | 후속 호출마다 재검사·두 active clients 차단 E3. subscription/push 기반 revocation event 전달/idle process 중단·SLO는 미완료 |
| FR-308 / 561 | 완료 | FG19. release/reason/status/인증 report 링크·비밀비노출. last safe 대안 상세 UX는 FG20 부분 |
| FR-309 / 562 | 완료 | FG16/17. byte-preserving stdout·ID/frame/초기화 guard·stderr redaction E3 |
| FR-310 / 563 | 완료 | FG16. legacy initialize revisions와 2026-07-28 stateless _meta, actual SDK compatibility tests. **외부 remote metadata assurance와 다른 요구** |
| FR-401 / 569 | 완료 | OB01/02, E5 실제 OTLP exporter+local EVM 전체 trace 연결. substage/opscollector는 별도 부분 |
| FR-402 / 570 | 부분 | console 검색·상태/root/tx/expiry/history 및 demo vote UI 존재. 임의 tenant validator vote 검색까지 통합된 hydrated dashboard E2E 증거 없음 |

위 12개 권고는 완료 9, 부분 3, 미완료 0이다. 이는 담당 FR core 소계일 뿐 전체 제품 구현률이 아니다.
