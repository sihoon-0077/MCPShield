# 캡스톤 v2.0 증거 지도

기준: [최종 마스터 v2.0](MCPShield_캡스톤_최종_마스터문서_v2.0.md) §5의 40개 P0.
2026-09-22 구현 재개 시점의 **작업용 매핑**이다. 파일 존재를 완료로 세지 않는다.
최종 `완료 / 부분 / 미완료` ledger와 완료율은 같은 RC의 실행 결과·독립 리뷰를 확인한 후 확정한다.
옛 원본 감사의 70%나 18.56%를 이 문서의 완료율로 가져오지 않는다.

R = 기존 코드 재사용, F = 기존 경로 수정, N = 필요한 작은 신규 연결/검사.
아래 테스트는 검수 진입점이며, 한 파일의 PASS만으로 해당 행의 모든 조건이 완료되지는 않는다.

| ID | 재사용 근거 / 변경 유형 | 검수 및 남은 증거 |
|---|---|---|
| CAP2-001 | R: `services/resolver/`, `tests/security/registry-broker.test.mjs` | exact npm/tarball·mutable 고정·미지원/허용 출처 회귀 |
| CAP2-002 | R: `tests/security/npm-closure.test.mjs`, `prepared-binding.test.mjs` | 실제 builder·source/closure/image 교체 거부; Linux 실행 |
| CAP2-003 | R: `tests/security/prepared-observation.test.mjs`, `apps/gateway/test/protocol-guard.test.mjs` | 전체 pagination·정규화·description/schema/annotation 변경 |
| CAP2-004 | N: resolver의 작은 demo publisher 서명 검사 | 같은 키 safe/bad 실제 서명, 누락·다른 키·bytes 변조 거부; sidecar는 source 밖 |
| CAP2-005 | R/F: `services/resolver/`, `tests/api/scoped-preparations.test.ts` | resolver `retrievedAt`와 출처 존재. publisher 수준은 `b8ec89d`/`4225255`로 연결; `6fc9dcf` pinned baseline2.1 기반 계약 통합, 실제 재취득/API/validator 연결은 미완료 |
| CAP2-006 | R: `tests/api/prepared-fullcycle.test.ts` | 같은 source/runtime/policy·독립 validator·Gateway 실제 통합 |
| CAP2-101 | R: `tests/security/scanner.test.mjs`, `master-scanner.test.mjs` | 신호별 양성/음성·정상 허용 접근 검사 존재. `6fc9dcf` 설치 bytes·dependency 최소 diff 기반 검사; 실제 runtime 및 AI DTO 연결 남음 |
| CAP2-102 | R: `tests/security/scoped-semantic.test.mjs`, `ai-provider.test.mjs` | 로컬 응답 계약과 실제 모델 호출 증거 분리; 모델·예산 필요 |
| CAP2-103 | R: `tests/security/semantic-review.test.mjs`, `scoped-baseline.test.mjs` | `6fc9dcf` 현재 위험을 생략하지 않는 버전 고정 before/after DTO·합산 전송 한도 검사 통합. local synthetic 계약만 검증, 실제 runtime/모델 비교 및 API 연결 미완료; runtime 승인은 거부 |
| CAP2-104 | R: `tests/security/docker-sandbox.test.mjs` | Linux Docker 격리 필수; Windows SKIP은 완료 아님 |
| CAP2-105 | F: `tests/security/scoped-prepared.test.mjs`, `tests/api/prepared-fullcycle.test.ts` | JSON sink 계약 수정 후 실제 canary hash·identity 결합 재실행 |
| CAP2-106 | R: `tests/security/ai-probes.test.mjs`, `scoped-prepared.test.mjs` | 생성한 probe와 실제 실행 digest·인자·관찰 결합 |
| CAP2-107 | R/F: `tests/security/scoped-prepared.test.mjs`, `tests/api/scoped-validator.test.ts` | safe PASS·bound violation FAIL·AI 장애 ABSTAIN; 기대값 완화 금지 |
| CAP2-108 | R: `tests/security/scoped-policy.test.mjs`, `apps/dashboard/test/scoped-node-policy.test.tsx` | incomplete·test-only·관찰 범위 한계가 결과/화면에서 유지되는지 |
| CAP2-201 | R: `tests/contracts/release-registry-v2.test.ts` | EIP-712 recovery·domain/policy/root·expiry/nonce 거부 |
| CAP2-202 | F: `tests/api/scoped-validator.test.ts`, `prepared-fullcycle.test.ts` | `4fb62d7`에 scoped 세 키/프로세스 연결. safe A/B2→C3, bad C격리→A/B2FAIL; PID/주소/root/확정tx 검수 추가. 6개 local receipt는 native 실행 전 완료 증거가 아니며 새 Linux 실행 대기 |
| CAP2-203 | R: `tests/contracts/release-registry-v2.test.ts` | 고유 2-of-3·중복/비활성·불일치 회귀 |
| CAP2-204 | R: `tests/contracts/release-registry-v2.test.ts`, `apps/gateway/test/frame-expiry.test.mjs` | 격리 TTL·terminal revoke·승인 만료 우선순위 |
| CAP2-205 | R: `contracts/scripts/deploy-v2.ts` | Base Sepolia 실제 배포·safe/revoke tx·source/bytecode 확인 필요 |
| CAP2-206 | F: `apps/indexer/src/v2-indexer.ts`, `tests/api/v2-indexer.test.ts`, `v2-fullcycle.test.ts` | `6bfb51c` 블록별 event/audit/checkpoint 원자화·same-height/shorter-fork/rewind 경합 방어·관측시각/lag 통합. 실제 Ganache/SQLite rollback·역순중복·DB/provider reopen 검사 및 두 Gateway/OTLP 회귀. native PG 경합/최종 Linux·OS 재시작 증거와는 구분 |
| CAP2-207 | R: `tests/api/control-plane.test.ts`, `prepared-validator.test.ts` | off-chain 암호화/무결성·on-chain 필드·최종 공개 secret 검사 |
| CAP2-301 | R: `scripts/demo/mcp-client.mjs`, `apps/gateway/test/gateway.test.mjs` | 실제 SDK stdio 통신·framing·stderr |
| CAP2-302 | R: `apps/gateway/test/prepared-docker.test.mjs` | exact identity 거부 시 후보 start 0건 및 safe 양성 대조군 |
| CAP2-303 | R: `apps/gateway/test/protocol-guard.test.mjs`, `prepared-docker.test.mjs` | 초기 전체 표면 확인·미선언 tool·정리 |
| CAP2-304 | R: `apps/gateway/test/terminal-revocation-race.test.mjs`, `prepared-docker.test.mjs` | 세션 후속 호출 revoke/expiry·검사/전달 경합 |
| CAP2-305 | R: `apps/gateway/test/signed-admission.test.mjs`, `admission-fallback.test.mjs` | strict 불명/stale/서명 오류 fail-closed |
| CAP2-306 | N: 기존 `benchmarks/agent-mcp-harness.mjs`와 SDK Gateway 연결 | 실제 모델 선택→실제 도구 결과 trace; fake provider는 계약 검사만 |
| CAP2-307 | R: `tests/api/prepared-fullcycle.test.ts`, `v2-fullcycle.test.ts` | 별도 A/B 프로세스·캐시·동일 testnet tx 이후 차단 시각 |
| CAP2-401 | F: `apps/api/src/chain-outbox.ts`, 기존 SQL queue | durable attempt·backoff·DLQ·receipt 불명 때 nonce 보호·PG 회귀 |
| CAP2-402 | R: `tests/api/control-plane.test.ts`, `preparations.test.ts` | 400/401/403/409·역할·임의 명령/키/경로 입력 거부 |
| CAP2-403 | R: `apps/dashboard/test/control-integration.test.mts`, `workflow.test.tsx` | 판정/tx/admission 상호 로그·한국어 사용자 오류 실제 조회 |
| CAP2-404 | R: `apps/dashboard/test/preparation-integration.test.mts` | publisher/행동 안전 분리·고정 한국어 오류 UI 통합. SSR/forms 성공과 실제 브라우저 전체 조작은 구분; 후자 남음 |
| CAP2-405 | R/F: `.github/workflows/frontend-gateway-devops.yml` | 같은 RC의 필수 native gate PASS·0 SKIP·독립 리뷰 |
| CAP2-406 | R: 기존 `repeat-demo` workflow job·Compose | 기존 반복 job은 legacy V2 Docker fullcycle. 새 scoped publisher RC의 clean Linux 10/10으로 확장·실행해야 하며 과거 성공으로 대체 금지 |
| CAP2-407 | R: `docs/pitch/MCPShield_사업계획서_10p.html` | RC에 맞는 실제 PPTX/PDF·3분 영상·검수된 링크 필요 |
| CAP2-501 | R/N: `demo/fixtures/`, 기존 평가 harness | 개발셋 분리 정상20/공격20·family·두 사람 label 검토 필요 |
| CAP2-502 | R/F: `benchmarks/` | 동일 holdout의 5개 비교군 원자료·ABSTAIN/N/A 분모 |
| CAP2-503 | R/N: Agent harness + 실제 Gateway 연결 | 실제 모델 OFF/ON 반복·sink/action oracle; OS 격리 OFF 금지 |
| CAP2-504 | R: `scripts/ops/evaluate-admission.ts`, `benchmarks/` | `8569025` [local smoke 원자료800건](../benchmarks/results/admission-smoke-100-8569025-2026-10-01.json)·집계 대조 추가. hash 포함/warm-cold 구분·scan/Agent 비용·testnet revoke3사례는 남음 |
| CAP2-505 | R/N: 기존 평가·handoff·CI 결과 | RC/model/prompt/policy/image/dataset/chain 묶음·원자료·실패/한계 |

## 이번 실행 기록의 출처

- 최종 `6bfb51c` 로컬 전체466 PASS/0 FAIL/35 SKIP·세 smoke/build/forms3 PASS. 새 indexer 포함이며 native Linux/PG 경합·실제 모델/테스트넷 완료가 아니다. [동일 SHA의 범위·한계](capstone-progress-2026-09-22.md).

- `f1d2929` CI36744373202는 Node24/PG 성공, Node22 기본 검사·빌드 성공 후 native Docker readiness 시간 초과로 실패. `cee4f04` 최소 서버 조회 수정은 집중10 PASS/2 SKIP·독립 리뷰를 통과했으며 새 Linux 결과 대기다. `6fc9dcf` baseline 기반 Main 집중27 PASS/1 native SKIP. 전체 실행 및 native 여부는 [진행 기록](capstone-progress-2026-09-22.md)에서 SHA별로 구분한다.

- 후속 `2fa3bc2`: 전체 로컬455 PASS/0 FAIL/35 SKIP·세 smoke/build/forms PASS. 앞선 `4fb62d7` 전체의 간헐 RPC 실패는 해결 미확정이며 진단만 추가했다. 선행 publisher `5bad1e9` Linux는 Node22/24 실패·PG 성공; `86673f6` 테스트 호환 수정 이후 새 native 결과 대기. [실패 포함 최신 기록](capstone-progress-2026-09-22.md).

- 2026-10-01 최신 기록: [재개·publisher 연결·실패/수정 경계](capstone-progress-2026-09-22.md). 선행 `7df0453` Linux CI는 전체 SUCCESS. 후속 실패의 cleanup을 `cbf7760`, 파일 worker 상한을 `c53e016`에 반영했다. `c53e016` 기본 전체 검사453 PASS/0 FAIL/35 SKIP·세 smoke·production build·built HTTP forms3건 PASS. 새 publisher Linux/Docker 검증 전까지 같은 RC 완료율을 확정하지 않는다.

- 수정 전: [PR CI 35696784563](https://github.com/sihoon-0077/MCPShield/actions/runs/35696784563), head `9a251ae`. Node 22 scoped scanner 및 scoped API 두 FAIL. Node 24와 PostgreSQL job 성공은 별도 경로의 증거다.
- 최초 수정: `35019f6`의 두 authored fixture가 sink의 기존 JSON 계약을 사용하도록 수정. scanner/validator guard는 변경하지 않았다.
- 로컬 집중 검사: Node 24.13.0 / Windows, scoped scanner + prepared fullcycle 총 16 중 13 PASS, 3 Docker SKIP. 실제 Linux 성공을 뜻하지 않는다.
- Linux 재검증: [PR CI 35736644460](https://github.com/sihoon-0077/MCPShield/actions/runs/35736644460), head `35019f6`. 이 지도 작성 시 진행 중이며 결과를 확정하지 않았다.
- 최종 통합 결과는 [실행 계획의 진행 로그](capstone-implementation-plan.md)에 SHA별로 추가한다.

## 외부 의존

실제 AI의 제공업체/모델·전송 허용 입력·비용 상한, Base Sepolia 전용 키/RPC/test ETH·거래 승인,
독립된 두 사람의 holdout label 검토가 필요하다. 없으면 해당 요구를 부분으로 남기고 실제 성공을 합성하지 않는다.
기존 공개 `/try`와 `/mcp`는 이 구현 작업만으로 변경/재배포되지 않는다.
