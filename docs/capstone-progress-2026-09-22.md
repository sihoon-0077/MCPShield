# MCPShield 캡스톤 v2.0 — 1차 구현 결과

2026-09-22 KST. 통합 기능/검사 기준 `c3c46dc`, 브랜치 `master/main`.
**전체 v2.0 완료 보고가 아니다.** 기존 50% 사용량 중단 조건은 사용자 재개 요청으로 해제했다.
기준은 [최종 마스터 v2.0](MCPShield_캡스톤_최종_마스터문서_v2.0.md)의 P0 40개다.

## 2026-10-01 KST — admission 원자료 체크포인트 `8569025`

- 기존 측정기에 `--raw-samples`만 추가했다. 기본 출력은 그대로이며 smoke에서만 허용하고 matrix/plan 혼용은 거부한다. 8개 경로 × 최대 1,000회 = 8,000건 상한, 고정 필드와 오류 코드만 출력한다. 원문 오류·키·후보 내용은 기록하지 않는다.
- 아래 명령을 깨끗한 `8569025185a1565ddadb342d16477bbe18c71cf2`에서 실제 실행했다. 시작/종료 Git SHA·파일 hash·작업 트리 상태가 동일했다. 측정 시각은 `2026-09-30T15:01:34.298Z` = 10월 1일 KST다.

```sh
node --import tsx scripts/ops/evaluate-admission.ts --requests 100 --identities 4 --concurrency 4 --raw-samples
```

- [추적 가능한 800건 JSON](../benchmarks/results/admission-smoke-100-8569025-2026-10-01.json): phase당 100건이며 개별 latency는 반올림하지 않았다. 원자료에서 p50/p95/p99/max·ALLOW/BLOCK/예상 fail-closed·cache·원인별 건수를 재계산해 모든 집계와 일치함을 확인했다. 순서는 완료 순서가 아닌 phase와 요청 시작 index다. 요약의 `throughputQps`는 실제 전체 phase 경과 시간으로 계산하며 개별 latency 합계로 재구성하는 값은 아니다.

| 측정 경로 | p50 ms | p95 ms | 결과 |
|---|---:|---:|---|
| strict HTTP + local EVM, 동일 identity | 121.291 | 163.023 | ALLOW 100 |
| strict HTTP + local EVM, 4 identities | 89.685 | 135.115 | ALLOW 100 |
| 주입한 API 장애, balanced 읽기·유효 signed cache | 0.849 | 0.958 | ALLOW 100 |
| 주입한 API 장애, strict 읽기 | 0.308 | 0.577 | 예상 fail-closed 100 |
| 주입한 API 장애, balanced 쓰기 | 0.542 | 1.120 | 예상 fail-closed 100 |
| 주입한 API 장애, 만료 signed cache | 0.559 | 1.875 | 예상 fail-closed 100 |
| 실제 HTTP + 주입한 RPC 장애 | 4.456 | 7.365 | 예상 fail-closed 100 |
| 실제 HTTP + local EVM 폐기 증거 | 80.562 | 101.154 | signed BLOCK 100, unsafe ALLOW 0 |

- 환경: Windows, Node24.13.0, SQLite WAL, loopback HTTP, local Ganache, concurrency4. API 장애는 즉시 실패를 주입했으므로 TCP timeout 지연이 아니다. Ganache의 Node24 µWS fallback 경고가 있었으며 stderr를 JSON 증거에 섞지 않았다.
- 측정 범위는 admission 호출 시작→결정/예상 fail-closed다. scanner는 합성 report이며 **파일 hash·프로세스 시작·warmup/control 검사·테스트넷·matrix를 포함하지 않는다**. 이전 날짜 smoke와 통제된 성능 비교가 아니며 p99 안정성·production 처리량/SLO·CAP2-504 전체 완료를 주장하지 않는다.
- 같은 구현의 전체 `npm test` exit0: **445 PASS / 0 FAIL / 35 SKIP** (Backend150/12, Security133/19, Gateway120/3, Dashboard42/1; PASS/SKIP). 세 smoke PASS. Security는 별도 재실행도133/0/19다. 집중 측정기 검사12 PASS/0 SKIP 및 TypeScript PASS, 독립 reviewer 확인. 가장 최근 전체 production build는 선행 `8f06733`에서 성공했으며 이후 변경은 측정기/회귀 검사뿐이다.
- 원자료는 별도 Reviewer도 독립 재계산해 통과했다. SHA/boundary snapshot·406파일·11개 raw 필드 whitelist와 문서 수치를 대조했으며 긴 측정을 새로 실행하거나 파일을 수정하지 않았다.

### 같은 날 Linux 통합 검증 완료 — `7df0453`

[CI36732591060](https://github.com/sihoon-0077/MCPShield/actions/runs/36732591060)는 `7df04539a7a1434eeab71fba919ad3bd0662b6e9`에서 **SUCCESS**로 종료됐다. 2026-09-30 15:16:52 UTC = 10월1일 00:16:52 KST 확인. 후속 원자료 측정기 `8569025`나 아직 작업 중인 publisher 연결 코드의 전체 CI로 전용하지 않는다.

| 검증 | 실제 결과 |
|---|---|
| Node22 / Node24 | 전체 job SUCCESS, 테스트·production build·built HTTP forms 성공 |
| PostgreSQL | 48 PASS / 0 FAIL / Docker health 1 SKIP; 실제 SQL retry/DLQ 및 별도 빈 DB로 백업 복원 성공 |
| builder 보안 | 실제 이미지 재빌드·Trivy HIGH/CRITICAL gate PASS. 예외/차단 기준 완화 없음 |
| npm 준비 / Gateway·Agent / scoped scanner | 별도 native 단계 모두 PASS; Agent/분석 모델은 로컬 합성 응답 계약 |
| OCI 독립 스캔 / 전체 폐기 경로 | 실제 native 실행 PASS; 앞선 오류 재현 지점의 signed REVOKED 및 두 Gateway 차단 기대값 유지 |
| prepared v1 / scoped Node v2 전체 경로 | 각각 실제 Docker→독립 검증자 프로세스→V2→Gateway 단계 PASS |
| 격리 / Compose / 관측성 | 실제 Linux sandbox, Docker→V2→두 Gateway, 전체 Compose 기동, 인증된 Grafana provisioning·exporter→collector→Prometheus 합성 metric 관측 PASS |
| production audit / tracked secret 검사 | 기존 기준 PASS. 앞선 MODERATE 전이 의존성 기록은 별도 잔여 위험 |

빠른 suite의 환경별 SKIP은 뒤 명시적 native/PG 단계와 구분했다. OCI 구성 스캔과 scoped Node fullcycle은 앞 단계에서 SKIP 후 각 전용 단계에서 실제 PASS했다. PR에서 실행하지 않는 `repeat-demo`, `signed-image` job과 failure-only 진단 단계의 SKIP은 정상 조건이다. **최종 RC clean10/10·이미지 서명·공개 배포·실제 AI·Base Sepolia 성공을 의미하지 않는다.**

## 2026-09-30 재개 기록

### 최신 보안 이미지 체크포인트 — `8f06733`

- `6f7fe17`의 [Linux CI 36730385934](https://github.com/sihoon-0077/MCPShield/actions/runs/36730385934)는 **FAILURE**다. Node24 job과 PostgreSQL job은 성공했다. PG는 48 PASS / 0 FAIL / Docker health 1 SKIP이며 실제 SQL outbox·별도 DB 백업/복원은 실행됐다.
- Node22의 builder 이미지 검사에서 HIGH 3건이 발견되어 뒤 native Docker 단계가 실행되지 않았다. 따라서 이 run은 앞선 OCI head 경합 수정의 native 효과를 검증하지 못했다. [원본 보고서 artifact](https://github.com/sihoon-0077/MCPShield/actions/runs/36730385934/artifacts/11105770873)는 기존 CI 정책상 1일 보존이다.
- 실제 설치 경로는 `usr/local/lib/node_modules/npm/node_modules/` 아래다. `brace-expansion@5.0.9`의 CVE-2026-102276/102278 두 건과 `undici@6.27.0`의 CVE-2026-19534 한 건이다. 공식 수정 안내: [brace parseCommaParts](https://github.com/juliangruber/brace-expansion/security/advisories/GHSA-6j4f-fj2g-mc7p), [brace nested groups](https://github.com/juliangruber/brace-expansion/security/advisories/GHSA-qhr7-859c-m2p7), [undici WebSocket](https://github.com/nodejs/undici/security/advisories/GHSA-rfgv-xxqx-mfg5).
- `8f06733`: 기존 SRI 검증 tarball 교체 절차로 `brace-expansion@5.0.11`, `undici@6.28.1`을 고정했다. Main·Reviewer가 공식 registry metadata와 실제 압축 bytes의 SHA-512를 각각 확인했다(12,007 / 295,788 bytes). 같은 major와 기존 dependencies/engines를 유지한다. root lock에는 해당 실행 패키지가 없어 수정하지 않았다.
- 기존 `closure-files.mjs`에 정확한 패치 목록을 모아 이미지 label, 설치 버전, 생성 report, 재검증 consumer의 불일치를 막았다. HIGH/CRITICAL 0건 gate·격리·ignore-scripts·고정 digest 기준은 그대로다. Dockerfile 목록과 shared contract의 일치 및 HIGH/CRITICAL 거부 portable 회귀를 추가했다.
- `8f06733`과 동일 작업 트리 전체 `npm test` exit 0: **444 PASS / 0 FAIL / 35 SKIP** (Backend 149/12, Security 133/19, Gateway 120/3, Dashboard 42/1; 각 수는 PASS/SKIP). 세 smoke 및 `npm run build` 성공. Backend는 같은 코드로 별도 재실행도 149 PASS / 0 FAIL / 12 SKIP. 집중 13 PASS / 4 native SKIP, 별도 reviewer 9 PASS / 4 native SKIP.
- 이 수정 이후 Linux 이미지 재빌드·Trivy·후속 전체 native 결과는 새 CI에서 확인해야 한다. 로컬 Docker가 없어 이를 로컬 성공으로 주장하지 않는다. main 머지·공개 배포·유료 모델·테스트넷 전송 없음.
- 별도 `npm audit --omit=dev --json`은 HIGH/CRITICAL 0, MODERATE 7개 dependency 노드를 보고했다(`fast-uri` 두 advisory의 전이 영향 포함). 전체 취약점 0건이 아니며 이 batch에서는 root 의존성을 변경하지 않았다. 기존 CI 기준은 `--audit-level=high`다.

### 재개 시점부터의 경로 수정 이력

- 9월 22일 사용량 제한으로 중단한 뒤 사용자가 재개를 요청했다. 당시 Main `2fb36d6`, 원격 `e172651`, Backend worktree의 미커밋 trace 수정 2파일을 확인하고 보존했다.
- `3997871`에 trace 수정을 통합했다. `chain.submit` span 종료 후 retry/실패/DLQ 감사 로그가 worker trace에 붙던 원인을 공통 `fail()` 경로에서 수정했다. 기존 `withSpan`에 저장된 `action.trace_parent`를 전달한다. nonce·서명 bytes·상태 전이·재시도 상한은 바꾸지 않았다.
- 결정론적 회귀: foreign worker trace `ffff…`와 원래 요청 `aaaa…`를 구분해 retry/terminal/pre-submit DLQ 세 경로를 검사한다. 담당 worktree에서 outbox + 실제 local EVM/OTLP 8 PASS / 0 FAIL / PG 1 SKIP, 별도 telemetry 2 PASS, TypeScript PASS.
- Main `3997871`의 전체 `npm test` exit 0: Backend 147 PASS / 12 SKIP, Security 133 PASS / 19 SKIP, Gateway 120 PASS / 3 SKIP, Dashboard 42 PASS / 1 SKIP. **442 PASS / 0 FAIL / 35 SKIP**, 세 demo smoke 모두 PASS. `npm run build`의 backend TypeScript·Next.js production build도 PASS. 이 결과는 실제 모델·테스트넷·Windows에서 실행되지 않은 Docker 검사의 성공을 뜻하지 않는다.
- 종료된 `e172651` [CI 35741226333](https://github.com/sihoon-0077/MCPShield/actions/runs/35741226333)를 다시 확인했다. PostgreSQL·Node24 성공, Node22 실패다. Gateway/Agent·scoped Node native는 성공했지만 OCI 단계에서 API가 `BLOCK/UNVERIFIED/STATUS_UNAVAILABLE`을 반환해 `REVOKED` 증거 검사에 실패했다(`oci-fullcycle.test.ts:188`). 이전 run의 child rejection과 지점이 다르며 같은 원인이라고 단정하지 않는다.
- 해당 실패 때문에 후속 sandbox/Compose/관측성/image 검사 일부가 SKIP되었다. 전체 Linux 검증 성공으로 표기하지 않으며 main 머지·공개 배포도 하지 않았다.
- OCI 경합 보완은 테스트에만 적용했다. 마지막 악성 릴리스 prepare 뒤 자동 1초 채굴을 중지하고, 기존 validator vote의 명시적 `evm_mine` pump가 끝난 뒤 동일 head에서 폐기 증거를 확인한다. 긴 정상 분석 구간의 자동 채굴·production reader의 negative-head-change 거부·시간 제한·정확한 REVOKED 기대값을 유지한다. 실제 과거 실패의 내부 코드가 없어 이 경합이 유일한 원인이었다고 확정하지 않으며 Linux 재실행으로 확인한다.
- `8ad0a40`에 OCI 테스트 보완을 통합했다. Main의 outbox/OCI/helper 집중 검사 11 PASS / 0 FAIL / 2 native SKIP. 별도 Reviewer의 portable OCI 2 PASS / 1 native SKIP 및 reader/RPC 8 PASS / 0 SKIP, 변경 경계 리뷰 통과. 새 portable Ganache 검사는 실제 대기 거래를 수동 채굴하고 1.1초 후 head/hash가 변하지 않는지 확인한다.

## 이번에 실제 반영한 것

| 파트 | 반영 | 아직 구분해야 할 것 |
|---|---|---|
| Security | scoped 악성 fixture가 기존 sink JSON 계약을 사용하도록 수정; 실제 Ed25519 게시자 서명·고정 공개키·source bytes 검증 | 서명 유효성은 행동 안전성 아님. 게시자 설정의 API/UI·전체 pipeline 연결은 남음 |
| Backend | chain outbox 최대12회/5분, 1초→최대30초 backoff, DLQ·원인/시도 기록 | 불명확한 signed transaction은 삭제/재서명하지 않음. 해당 signer를 멈추고 운영자가 체인 사실을 확인 |
| Gateway | 기존 모델 결정 함수→MCP SDK→strict Gateway→실제 `list_messages` 호출 연결; 승인/후속 호출 identity 로그 | 로컬 가짜 모델 계약 검사와 실제 외부 모델 실증을 구분. 보호 ON 전용이며 OFF/ON ASR 아님 |
| 화면 | 체인 재시도 중단 한국어 안내·시도 횟수·다음 확인 시각 | 최신 공개 배포·실제 브라우저 전체 검수는 하지 않음 |
| Main/CI | 새3개 worktree, 교차 리뷰·통합; prepared Agent 및 PostgreSQL outbox native 테스트를 CI에 연결 | 새 통합 SHA의 Linux 전체 성공은 별도 확인 필요 |

ponytail 적용: 기존 resolver/hash·SQL outbox·Agent 판단 함수·MCP SDK를 재사용했다.
새 패키지·서비스·Redis/Kafka/RabbitMQ를 도입하지 않았다. 보안 guard·FAIL 기대값을 낮추지 않았다.
원본 `mcp/main`, 기존 worktree 및 공개 `/try`·`/mcp`를 보존했다.

## 로컬 검증

Windows / Node 24.13.0. `c3c46dc`에서 `npm test` exit 0.

| 검사 | PASS | FAIL | SKIP |
|---|---:|---:|---:|
| Backend / 계약 / 통합 | 144 | 0 | 12 |
| Security | 133 | 0 | 19 |
| Gateway | 120 | 0 | 3 |
| Dashboard | 42 | 0 | 1 |
| 합계 | **439** | **0** | **35** |

- Replay smoke, MCP SDK E2E, LIVE synthetic smoke 모두 PASS.
- `npm run build`: backend 타입 검사 및 Next.js production build PASS (`c690226`; 이후 변경은 CI 계약 테스트뿐).
- 빌드된 화면의 `MCPSHIELD_FORM_HTTP_TESTS=1` 검사: 3 PASS / 0 SKIP.
- 35 SKIP은 PostgreSQL·Linux/Docker·일부 opt-in 검사다. 위의 별도 HTTP 실행을 전체 suite의 SKIP에서 빼서 집계를 바꾸지 않았다.
- 신규 40개 증거 지도: P0 ID 40개, 중복 없음, master 순서와 정확히 일치.
- 초기 통합 검사에서 CI 명령 문자열을 고정한 회귀 테스트 1개가 실패했다. 새 native 검사 목록을 포함하도록 기대 계약을 갱신하고, 기존 image-signing 성공 조건을 유지하는 검사를 보강한 뒤 전체를 다시 실행했다.

## Linux CI와 리뷰

- 수정 전 `9a251ae`의 [CI 35696784563](https://github.com/sihoon-0077/MCPShield/actions/runs/35696784563)는 scoped scanner/API 2 FAIL이었다.
- fixture 수정 `35019f6`의 [CI 35736644460](https://github.com/sihoon-0077/MCPShield/actions/runs/35736644460)에서 기존에 실패하던 **scoped Node scanner 및 scoped API→독립 validator→Gateway native 두 gate가 모두 PASS**했다. Linux sandbox 격리·Node24·PostgreSQL job도 PASS했다. 이 기록 시 Node22의 후속 Compose 등 전체 job은 아직 종료 전이다.
- 이 CI에는 이후 게시자/재시도/Agent 변경이 없다. 결과를 새 통합 SHA의 native 성공으로 전용하지 않는다.
- Main과 별도 Security reviewer가 queue head/nonce 보존·Agent 결과 판정·키 분리·모델 증거 표기를 검토했다. 발견한 legacy unsigned queue 정체, PostgreSQL migration 기대값, scoped mail 응답 호환, 다중 호출 완료 오판은 수정했다.
- 새 통합 `fab3ed1`의 [CI 35738979192](https://github.com/sihoon-0077/MCPShield/actions/runs/35738979192): PostgreSQL job PASS(신규 outbox claim/backoff/계정 lease/signed DLQ 검사 포함, 47 PASS / 0 FAIL / 1 SKIP), Node24 job PASS. PostgreSQL의 1 SKIP은 Docker health opt-in 검사이며 SQL retry 검사의 SKIP이 아니다.
- 같은 통합 CI의 Node22 prepared Gateway/Agent native 단계는 실패했다. Windows의 SKIP을 성공으로 취급하지 않았기에 발견한 실패이며, 상세 로그 확인과 수정 전까지 해당 기능의 native 완료로 세지 않는다. scoped Node scanner 등 후속 native 단계는 별도로 성공했다.
- 두 Gateway 테스트가 같은 Docker daemon의 전체 컨테이너 목록을 검사하면서 병렬 실행되는 충돌을 교차 리뷰에서 발견했다. 누수 검사를 유지하고 `--test-concurrency=1`을 고정했으며, CI 명령 계약 검사 9개가 PASS했다. 실제 실패 로그 및 후속 native 결과 확인 전에는 이것만으로 원인 해결을 확정하지 않는다.
- 같은 SHA의 PR run에서는 OCI worker/validator native 단계도 실패했으나 push run에서는 성공했다. 원인 미확정으로 별도 추적한다. P0 Node 경로 성공과 P1 OCI 경로 성공을 혼동하지 않는다.
- 상세 로그 확보 후 구분: `fab3ed1`에서 신규 Agent native 자체는 PASS(실제 prepared Docker/SDK/Gateway, 가짜 모델)였다. 같은 단계의 기존 `prepared-docker.test.mjs:171` 전역 컨테이너 비교가 추가 CID 1개 때문에 실패했다. 전체 단계가 실패했으므로 Agent PASS만으로 통합 성공이라고 하지 않는다.
- OCI 실패는 `oci-fullcycle.test.ts:197`의 마지막 두 Gateway 차단 검사 중 child rejection이다. 그 이전 독립 validator·quorum·REVOKED admission 검사는 지나갔다. 기존 helper가 상세 원인을 지워 root cause는 아직 불명확하며, 테스트 전용 고정 allowlist 코드로 진단을 보강한다. raw 오류·토큰·키·경로는 출력하지 않는다.
- 후속 `e172651`의 [CI 35741226333](https://github.com/sihoon-0077/MCPShield/actions/runs/35741226333)는 순차 native 검사와 Agent 정리 검사를 포함한다. Node24·PostgreSQL job PASS, 기록 시 Node22 native는 진행 중이다. `fab3ed1`의 진행 중 run은 후속 push로 취소되었으며 이를 전체 성공으로 세지 않는다.
- `e172651`의 **순차 prepared Gateway/Agent native 단계 PASS**. 추가한 Agent의 정상/폐기 경로 컨테이너 정리 검사도 이 단계에 포함된다. 후속 OCI 등 전체 Node22 job은 별도 결과다.
- 후속 진단 통합 `2fb36d6`의 로컬 전체 재검사에서 backend 145 PASS / 1 FAIL / 12 SKIP: 기존 OTLP fullcycle의 trace 연결 검사가 실패했다. 독립 재실행은 PASS했지만 무시하지 않았다. 새 outbox의 retry audit가 `chain.submit` span 밖에서 caller trace를 기록하는 것이 원인으로 확인되어, 원래 action trace에 다시 연결하는 회귀 수정 대상이다. 기존 439 PASS는 이전 SHA 결과이며 이 실패를 덮는 최신 성공으로 표기하지 않는다.
- main 머지·Railway 재배포·테스트넷 거래·유료 모델 호출은 하지 않았다. 개발 PR은 검증 대기 상태로 유지한다.

## 로컬 성능 smoke (정식 평가와 구분)

깨끗한 `fab3ed1`에서 `node --import tsx scripts/ops/evaluate-admission.ts --requests 100 --concurrency 4 --identities 4` exit 0.
기존 측정기를 재사용했으며 8개 phase 각각 100회, 총 800회 집계다.

| 경로 | p50 | p95 | 결과 |
|---|---:|---:|---|
| strict HTTP + local EVM, 동일 identity | 63.238 ms | 82.821 ms | ALLOW 100/100 |
| strict HTTP + local EVM, 4 identities | 60.006 ms | 67.206 ms | ALLOW 100/100 |
| 폐기 후 admission | 48.572 ms | 54.201 ms | BLOCK 100/100, ALLOW 0 |

원본 집계는 로컬 `artifacts/capstone/admission-smoke-100-fab3ed1.json`에 있다(생성 artifact로 Git 제외).
실제 테스트넷·후보 hash/spawn 비용·개별 요청 지연 원자료를 포함하지 않아 CAP2-504 완료 증거가 아니다.
실행 중 Ganache의 Node24 µWS fallback 및 listener 경고가 있었다. 묵음 처리하거나 성능 실증의 환경 한계를 숨기지 않는다.

## 로그와 새 기능 확인 위치

- Dashboard `/console` → 릴리스 workflow의 **체인 작업**: 시도 횟수·다음 확인·자동 재시도 중단 안내.
- 인증된 `GET /v1/chain/actions/:actionId`: `attempts`, `retryStartedAt`, `nextAttemptAt`, `retryBudget`, `errorCode`.
- 인증된 `GET /v1/events`, 릴리스 history: `chain.action.retry_scheduled`, `chain.action.failed`, `chain.action.dead_letter`.
- Agent 실행: [Gateway README](../apps/gateway/README.md)의 환경/명령. `node benchmarks/gateway-agent.mjs`는 운영자 prepared identity·승인 설정·모델 opt-in 없이는 거부된다.
- 게시자 최소 검사: `node --import tsx --test tests/security/demo-publisher.test.mjs`.
- DB 변경/복구: [database README](../database/README.md). live DB에서 DLQ나 signed bytes를 지우고 재전송하면 안 된다.

## 다음 단계 / 완료로 세지 않은 것

1. 새 통합 SHA의 native PostgreSQL·prepared Agent·scoped source→validator→Gateway CI를 확인한다.
2. 게시자 검증을 운영자 source catalogue와 API/UI 증거 흐름에 연결한다.
3. 승인된 실제 모델로 Agent 정상 조회 및 scanner 의미 분석 증거를 확보한다. 모델/키·전송 범위·총 비용 상한이 필요하다.
4. Base Sepolia 실제 배포·승인/폐기 거래와 두 Gateway 반영을 검증한다. 테스트 전용 key/RPC/test ETH·거래 승인이 필요하다.
5. 독립 holdout 정상20/공격20·두 사람 label 검토·5개 비교군·실제 Agent OFF/ON·경로별100회 성능 측정을 수행한다.
6. 같은 RC의 clean E2E10회·브라우저 검수·PPTX/PDF·영상·최종 완료 ledger를 묶는다.

현재 CAP2 전체 완료율은 **아직 미산정**이다. [40개 증거 지도](capstone-evidence-map.md)는 검수 계획이지 완료 선언이 아니다.
실제 모델/체인/평가 증거가 없는 상태를 테스트 fixture 성공만으로 채우지 않는다.
