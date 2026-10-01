# MCPShield 캡스톤 v2.0 실행 계획

2026-09-22 재개. 기준은 [최종 마스터 v2.0](MCPShield_캡스톤_최종_마스터문서_v2.0.md)의 P0 40개다.
사용자가 과거 잔여 50% 중단 조건을 해제했다. 이전 목표·전체 감사 수치는 역사 자료다.
현재 CAP2 완료율은 아직 재산정하지 않았다. 코드 존재나 부분 테스트 성공을 전체 완료로 세지 않는다.

> **2026-10-01 현재 사용자 지정 작업 범위:** 이번 작업은 (1) 화면 중복 오류·이전 버전 선택·검사 요청·권한별 브라우저 검수, (2) 최신 baseline API/validator/chain/Gateway Linux/Docker 통합 검증·간헐 RPC 원인 확인·독립 리뷰까지만 진행한다. 실제 AI/테스트넷·평가·배포·제출물은 이번 작업에서 진행하지 않는다. 전체 v2.0 목표의 완료 조건을 축소한 것은 아니다.

## 첫 병렬 작업

| 역할 | 브랜치 | 현재 범위 | 근거/검수 |
|---|---|---|---|
| Main | master/main | 공통 기준·통합·CI·리뷰·증거 기록 | 최신 실패 job 확인, 각 변경 재검증 |
| Security·AI | capstone/security-v2 | scoped Node native ABSTAIN 원인 수정; synthetic publisher 서명 | CAP2-004/102/105/106/107, 기존 canary·서명 경계 회귀 |
| Blockchain·Backend | capstone/backend-v2 | scoped-v2 API/validator 경로 검증; 최소 chain retry 상한 검토 | CAP2-006/201/202/401, 기존 통합 테스트 재사용 |
| Frontend·Gateway | capstone/frontend-v2 | 기존 Agent 결정 함수와 실제 MCP Gateway 연결 | CAP2-306/503, 계약 응답과 실제 모델 결과 출처 구분 |

## 작업 원칙

- ponytail: 기존 모듈·표준 라이브러리 우선, 새로운 프레임워크·범용 플랫폼 도입 없음.
- native 실패의 기대값 FAIL을 ABSTAIN으로 낮추거나 판정을 강제하지 않는다.
- 공개 데모 `/try`, `/mcp`, 원본 브랜치·worktree를 보존한다.
- source identity·policy·report 결합, 최소권한·fail-closed·비밀 분리는 축소하지 않는다.
- 실제 모델·테스트넷은 명시적으로 준비된 권한·secret·비용 상한이 있을 때만 실증한다.
- Windows에서 Docker native 검사가 SKIP되면 Linux 성공으로 보고하지 않는다.
- P0 Node 경로를 고치기 위해 미통합 OCI v2 전체를 가져오지 않는다.

## 재개 시 확인한 상태

- 통합 코드 기준 `9a251ae`, 마지막 기능 기준 `7bac78a`.
- 실제 local `docker` 명령을 찾지 못했다. native Linux 검증 환경은 별도 확인이 필요하다.
- 기존 Node scoped scanner/API의 두 ABSTAIN 실패는 과거 감사에 기록되어 있다. 최신 CI를 다시 확인한다.
- v2.0 문서와 handoff 포인터는 이전 작성 작업의 변경으로 보존했다.

## 남은 외부 증거

- 준비된 Linux Docker 및 immutable builder/image의 실제 통합 실행.
- 실제 AI provider와 Agent 실증(로컬 가짜 HTTP 응답과 구분).
- Base Sepolia 실제 계약·승인/폐기 tx·두 Gateway 상태 반영.
- 독립 holdout 20+20, 5개 비교군, 정상 작업 성공률·ASR·성능 원자료.
- 최종 RC의 브라우저 검수·clean 재현·PPT/PDF·영상.

## 진행 로그

- 2026-10-01 제한 범위 후속: `f339e53` 콘솔 형제 key3곳 수정·실제 브라우저 QA와 독립 리뷰 완료. `f0f407e` CI36807645907에서 새 baseline2.1 API→세validator→V2→두Gateway1 PASS/0SKIP·PG baseline1 PASS/0SKIP·Compose/Grafana 성공, 최종 Fastify/grpc audit로 전체 FAILURE. `83a8597` 두 패키지 patch와 독립 리뷰 후 전체 로컬478 PASS/38SKIP·세smoke/build/forms4 PASS, production audit0. 간헐RPC는 재현되지 않아 원인 미확정이며 새 patch SHA Linux 검증은 별도 확인한다. 공개 배포·실제 AI·테스트넷 없음. [증거와 제한](capstone-progress-2026-09-22.md).

- 2026-10-01 후속: `4d58923`/`743db4c` baseline API/worker/독립 validator와 `d37a929`/`565602f` UI를 통합하고 `8f01679` test setup cleanup을 보완했다. `8f01679` 전체 npm test·세 smoke·production build·built forms PASS. `1505b70`에 별도2.1 native/PG gate를 추가했다. 선행6dd의 CI36749815609는 native baseline15/0SKIP·scoped2.0 세validator1/0SKIP·Compose/Grafana·PG 성공 후 Next critical audit로 FAILURE. `3bc90db` Next16.3.8/fast-uri patch의 local production audit0; 새 CI·후속독립리뷰는 대기. 평가 계약 초안은 별도 Security worktree에 미검증 상태로 보존했다. 상세는 [진행 기록](capstone-progress-2026-09-22.md)의 최상단을 따른다.

- 2026-10-01 후속: `3746bd9` baseline2.1 runtime과 `b759be8` 정상/악성 업데이트 회귀를 독립 리뷰 후 통합했다. Main focused32 PASS/0 FAIL/2 native SKIP. `a1f7ac5`는 기존 immutable builder 뒤 별도 순차 native CI gate를 추가하고, 독립 validator의 기존 `ValidatorSources.baselines` 설정 계약을 기록한다. CI 명령/서명 gate 회귀9 PASS. API/worker/validator 연결은 별도 Backend 구현 중이며 외부 AI·실제 Docker 성공을 이 portable 결과로 대체하지 않는다.

- 2026-10-01 후속: indexer의 감사 저장·checkpoint 실패 및 동시 reorg/shorter-fork 저장 경합을 재현하고 기존 `forTenant` 블록 원자화·checkpoint/parent fence로 보완했다. 독립 최종 리뷰 후 `d423102`/`edb3843`/`6bfb51c`에 통합. 담당자 실제 Ganache/SQLite+기존 두 Gateway OTLP2 PASS, Reviewer 실제EVM1 PASS 및 별도 SQL interleaving 재현. 최종 Main6bfb51c 전체466 PASS/0 FAIL/35 SKIP·세 smoke/build/forms3 PASS. 새 Linux 성공은 별도 확인한다. API/validator baseline2.1 연결은 Security stable runtime 계약 확인 뒤 이어간다.

- 2026-10-01 후속: `f1d2929` CI36744373202는 Node24/PG 성공, Node22 기본 검사·빌드 후 Docker readiness 시간 초과로 실패했다. `cee4f04`는 제한시간을 유지하고 서버 OS만 조회하도록 수정했다(집중10 PASS/2 SKIP·독립 리뷰). `6fc9dcf`에 baseline2.1 기반 계약을 통합했다(Main 집중27 PASS/1 SKIP·Reviewer 신규9 PASS). runtime 재취득/API/validator 연결과 실제 모델 증거는 별도 잔여다. indexer block 원자화 draft는 짧은 fork 동시성 경합을 추가 재현하여 보완·리뷰 중이며 완료로 세지 않는다.

- 2026-10-01 후속: publisher Linux `5bad1e9`는 Node22/24 두 테스트 호환 문제로 실패, PG는 성공했다. `86673f6` 테스트만 수정하고 세 검증자 `4fb62d7`을 통합했다. 첫 전체는 Backend157/1/12로 OTLP 내부 EVM RPC 실패, 단독 실행은 성공했다. 근본 원인 미확정으로 고정 단계 진단 `2fa3bc2`를 추가했고 전체 재실행455 PASS/0 FAIL/35 SKIP·세 smoke/build/forms 성공. 새 native 결과는 별도 확인하며 CAP2-202 완료로 아직 세지 않는다. scoped baseline2.1·V2 indexer 원자성/재시작 검수는 승인된 후속 병렬 작업이다.

- 재개 준비: 스킬·협업 규칙·v2.0 요구사항을 확인하고 새 파트 브랜치를 준비한다. 기능 완료 선언은 아니다.
- Main + 3개 새 worktree를 `b11ed63`에서 생성했다. 기존 worktree는 보존하고 설치된 의존성을 재사용한다.
- [40개 P0 증거 지도](capstone-evidence-map.md)를 만들었다. 작업용 매핑이며 최종 감사/완료율은 아니다.
- 원인 확인: 두 scoped malicious fixture가 `/events`에 raw text를 보내 HTTP 415로 거절되었다. 실제 canary event가 없고 AI도 없어서 ABSTAIN인 것은 올바른 방어 동작이었다.
- `5bac927` / `35019f6`: 기존 sink의 JSON `{canary}` 계약으로 두 fixture를 수정했다. safe/FAIL 기대값·보안 guard는 유지했다. trusted sink 회귀 검사도 추가했다.
- 로컬 집중 검사: 13 PASS / 3 native Docker SKIP. `35019f6`을 기존 `master/main` PR에 push하고 Linux CI `35736644460`을 시작했다. main 머지·공개 배포는 하지 않았다.
- `35019f6` Windows 전체 `npm test`: backend 138 PASS / 11 SKIP, security 129 PASS / 19 SKIP, Gateway 110 PASS / 2 SKIP, dashboard 41 PASS / 1 SKIP, 세 demo smoke PASS. 합계 418 PASS / 33 SKIP / 0 FAIL이며 Docker·PostgreSQL 미실행을 포함한다.
- 같은 SHA의 Linux CI에서 기존 실패였던 scoped Node scanner native gate가 실제 PASS했다. Node 24 job·PostgreSQL job도 PASS. scoped API native와 나머지 Node 22 단계는 아직 최종 결과 확인 전이다.
- `d8faa98`: 기존 resolver에 운영자 고정 공개키를 받는 demo publisher 검사를 추가했다. 기존 safe/bad source의 공개 서명 sidecar만 저장하며 개인키는 저장하지 않았다. Main의 실제 resolver 검수 4 PASS / 0 SKIP, backend typecheck PASS. 서명 유효성을 행동 안전성으로 승격하지 않는다.
- 교차 리뷰: Main이 outbox의 과거 unsigned/null-domain 행에 의한 queue starvation 및 Agent의 기존 scoped tool 응답 형식 불일치를 발견했다. 담당자가 회귀 검사를 추가해 수정 중이다. Security reviewer는 PostgreSQL migration 개수 기대값과 새 claim SQL 검증 누락도 확인했다.
- 후속 통합 `c3c46dc`: 위 리뷰 지적을 수정하고 게시자·bounded outbox·Agent bridge·한국어 DLQ 안내를 모두 통합했다. 신규 native 검사를 CI 명령과 CI 계약 회귀 검사에도 연결했다.
- 새 전체 로컬 검사: **439 PASS / 0 FAIL / 35 SKIP**, 세 demo smoke PASS, backend/dashboard production build PASS. 결과·commit·외부 미검증 범위는 [1차 구현 결과](capstone-progress-2026-09-22.md)에 기록했다.
- 최초 fixture 수정 SHA `35019f6`의 기존 실패 두 native gate 모두 실제 PASS 확인. 후속 기능의 CI와는 분리한다. 새 통합본을 같은 PR에 push하면 기존 진행 중 run이 workflow concurrency 정책으로 취소될 수 있으므로 개별 gate 성공을 전체 run 성공이라고 하지 않는다.
- 통합 `fab3ed1` native PostgreSQL outbox PASS. Gateway native 실패 조사 중 공유 daemon 누수 검사의 병렬 충돌을 발견해 두 test file을 순차 실행하도록 수정했다. 가드·누수 검사는 유지하며 실제 재실행으로 확인한다.
- 2026-09-30 재개: 미커밋 상태로 보존된 trace 수정 2파일을 검수하고 `3997871`로 통합했다. 재시도/terminal/DLQ 감사 기록이 원래 action trace에 남는다. 전체 로컬 **442 PASS / 0 FAIL / 35 SKIP**, 세 smoke 및 production build PASS. 종료된 이전 CI의 OCI `STATUS_UNAVAILABLE` 실패는 별도 조사 중이며 전체 Linux 성공·v2 완료를 선언하지 않는다.
- 2026-09-30 후속: `6f7fe17` CI의 Node24/실제 PG는 성공했지만 builder HIGH 3건으로 Node22가 중단됐다. `8f06733`에서 기존 SRI 검증 절차로 brace-expansion5.0.11/undici6.28.1을 적용하고 label·설치 검사·report를 shared exact patch set으로 일치시켰다. 전체 로컬 **444 PASS / 0 FAIL / 35 SKIP**, 세 smoke/production build 및 별도 reviewer 통과. 새 Linux 이미지 검사 전에는 해결 검증 완료로 세지 않는다. CVE/원본 run/잔여 moderate는 [진행 기록](capstone-progress-2026-09-22.md)에 남겼다.

- 2026-10-01 KST: `8569025`에 기존 admission smoke의 opt-in 원자료(최대8,000건)를 추가하고 깨끗한 SHA에서 phase당100회·총800회를 실제 측정했다. 추적 JSON·SHA·환경·집계 대조·제외 범위는 [진행 기록](capstone-progress-2026-09-22.md)에 연결했다. 전체 로컬445 PASS/0 FAIL/35 SKIP·세 smoke PASS. `7df0453` Linux의 builder security와 OCI 전체 폐기 경로는 PASS, 전체 run은 진행 중이며 후속 측정기 SHA의 CI와 구분한다.

- 2026-10-01 KST 후속: `7df0453` [CI36732591060](https://github.com/sihoon-0077/MCPShield/actions/runs/36732591060) 전체 SUCCESS. Node22/24·PG·필수 native·Compose·실제 관측 파이프라인 성공을 완료 로그로 확인했다. 빠른 suite의 SKIP과 별도 실제 실행을 구분했고 dispatch 전용10회 반복/이미지 서명은 SKIP이다. 다음 publisher API/validator/UI 연결은 별도 worktree에서 구현·리뷰하며 이 선행 성공으로 대신하지 않는다.

## publisher pipeline 연결 — 설계 당시 경계 및 현재 결과

아래 설계는 `b8ec89d`/`4225255`와 Dashboard `235d52b`/`751cd5f`/`6edbe6a`로 통합했다. additive operator 계약은 `1e34a82`에 기록했다. 독립 source/key 재검증·암호화 publisher leaf·준비 identity 충돌 보존·행동 안전과 분리된 화면을 구현했다. 이후 초기화 실패 cleanup을 `cbf7760`, 테스트 파일 worker 상한을 `c53e016`으로 수정했다. 같은 구현의 기본 전체 검사453 PASS/0 FAIL/35 SKIP·세 smoke·production build·built-form HTTP3건 PASS. 새 Linux/Docker/PG CI는 별도 확인한다. [실패 이력을 포함한 검증 수치와 미완료 경계](capstone-progress-2026-09-22.md)를 먼저 읽는다. 아래 문단은 구현 전 설계 기록이다.

현재 서명 검증은 resolver에 연결되었지만 API/독립 validator의 운영자 설정은 아직 연결되지 않았다.
API source 등록, scoped 준비/재검증, validator 독립 수집 모두 같은 실측 source identity에 대해 검증해야 한다.
신뢰 공개키는 요청 body나 후보 metadata가 아닌 운영자 catalogue에서 읽고, proof를 기존 frozen/configHash·암호화 evidence bundle에 결합한다.
기존 서명된 공개 mail fixture와 native prepared scoped fixture는 서로 다르다. 공개 fixture를 바꿔 replay identity를 깨지 않는다.
서명 실패는 source 인증 실패/ABSTAIN과 연결하고, 서명 성공을 행동 PASS로 승격하지 않는다.
9월 30일 읽기 전용 재검토에서는 `scoped-config.ts`, `control-plane.ts`, `preparation-worker.ts`,
`scoped-verification.ts`, `prepared-verification.ts`의 기존 경로 재사용을 확인했다. 새 DB/서비스는 필요 없으며,
strict catalogue에는 별도의 명시적 publisher section 확장이 필요하다. `prepared/source-identity.json`의 고정 5필드를 바꾸지 말고
기존 Merkle bundle에 별도 publisher proof를 넣고 독립 validator가 자기 source/key로 재검증한다. 최초 prepare와 재스캔 양쪽을 다뤄야 한다.
기존 공개 mail fixture에는 bin이 없고 prepare는 fixture sourceType를 거부하므로, native scoped-synthetic fixture 전체를 만든 뒤
같은 임시 demo key로 safe/bad 각각 서명하는 E2E를 우선한다. 이 설계 검토는 API/UI 연결 구현 완료가 아니다.

## 재작성 방지 확인

- 게시자: 기존 resolver snapshot/hash + Node `crypto`를 사용한다. 기존 MOCK 표시에는 실제 서명 검사가 없어 작은 검증 함수와 공개 sidecar만 필요했다. 최소 검사는 같은 키의 두 버전 검증 및 bytes/키/누락 거부다.
- 체인 전송: 기존 SQL outbox·lease·signed transaction을 유지한다. 기존 경로에 retry 상한이 없어 additive migration과 bounded backoff를 넣는다. 최소 검사는 응답 유실 때 동일 bytes 재전송, 횟수 초과 DLQ 및 nonce 보호다.
- Agent: 기존 모델 결정 함수와 MCP SDK client를 연결한다. 기존 scanner-only callback으로는 실제 Gateway 집행을 증명할 수 없다. 최소 검사는 모델 선택→Gateway 호출 및 선택 뒤 폐기 시 미전달이다.
