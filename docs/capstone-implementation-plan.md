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
