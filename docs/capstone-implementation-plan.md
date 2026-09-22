# MCPShield 캡스톤 v2.0 실행 계획

2026-09-22 재개. 기준은 [최종 마스터 v2.0](MCPShield_캡스톤_최종_마스터문서_v2.0.md)의 P0 40개다.
사용자가 과거 잔여 50% 중단 조건을 해제했다. 이전 목표·전체 감사 수치는 역사 자료다.
현재 CAP2 완료율은 아직 재산정하지 않았다. 코드 존재나 부분 테스트 성공을 전체 완료로 세지 않는다.

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

## 다음 publisher pipeline 연결 시 주의

현재 서명 검증은 resolver에 연결되었지만 API/독립 validator의 운영자 설정은 아직 연결되지 않았다.
API source 등록, scoped 준비/재검증, validator 독립 수집 모두 같은 실측 source identity에 대해 검증해야 한다.
신뢰 공개키는 요청 body나 후보 metadata가 아닌 운영자 catalogue에서 읽고, proof를 기존 frozen/configHash·암호화 evidence bundle에 결합한다.
기존 서명된 공개 mail fixture와 native prepared scoped fixture는 서로 다르다. 공개 fixture를 바꿔 replay identity를 깨지 않는다.
서명 실패는 source 인증 실패/ABSTAIN과 연결하고, 서명 성공을 행동 PASS로 승격하지 않는다.

## 재작성 방지 확인

- 게시자: 기존 resolver snapshot/hash + Node `crypto`를 사용한다. 기존 MOCK 표시에는 실제 서명 검사가 없어 작은 검증 함수와 공개 sidecar만 필요했다. 최소 검사는 같은 키의 두 버전 검증 및 bytes/키/누락 거부다.
- 체인 전송: 기존 SQL outbox·lease·signed transaction을 유지한다. 기존 경로에 retry 상한이 없어 additive migration과 bounded backoff를 넣는다. 최소 검사는 응답 유실 때 동일 bytes 재전송, 횟수 초과 DLQ 및 nonce 보호다.
- Agent: 기존 모델 결정 함수와 MCP SDK client를 연결한다. 기존 scanner-only callback으로는 실제 Gateway 집행을 증명할 수 없다. 최소 검사는 모델 선택→Gateway 호출 및 선택 뒤 폐기 시 미전달이다.
