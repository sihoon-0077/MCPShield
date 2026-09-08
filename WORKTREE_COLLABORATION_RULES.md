# MCPShield Worktree 협업 규칙

이 문서는 MCPShield 해커톤 프로토타입을 여러 worktree에서 병렬 개발할 때 사용하는 역할, 코드 소유권, 인터페이스, 병합 및 리뷰 규칙을 정의한다.

## 2026-09-08 마스터 문서 구현 단계

사용자가 마스터 문서 전체 구현을 요청했으므로, 이번 `master/*` 브랜치에서는
기존 MVP의 범위 제한(3.10, 11절)을 완료 기준으로 사용하지 않는다.
요구사항·수용 테스트별 실제 구현과 검증 증거는 `docs/master-implementation-plan.md`에서 관리한다.
문서의 미래 운영 규모·목표 성능·독립 검증기관 참여를 이미 달성한 기능으로 표기하지 않는다.

| 역할 | 작업 브랜치 | 추가 소유 범위 |
|---|---|---|
| Main | `master/main` | 공통 의존성·계약 승인, CI·루트 Docker·운영 문서, 통합 검증 |
| Security·AI | `master/security-ai` | `services/resolver/`, 기존 보안 영역 |
| Blockchain·Backend | `master/blockchain-backend` | `apps/reconciler/`, API·컨트랙트 테스트, 기존 백엔드 영역 |
| Frontend·Gateway | `master/frontend-gateway` | 기존 UI·Gateway·데모 영역, 루트 CI·Docker는 Main에게 요청 |

`mcp/main`과 기존 공개 `/try`, `/mcp`는 호환성을 유지한다. 새 API는 `/v1`로 추가하고
기존 `/api` 스키마를 재정의하지 않는다. 외부 서비스의 유료 자원·실제 키가 필요한
검증은 로컬 대체 결과와 구분하며, 설정이 없다고 보안 검사를 우회하지 않는다.


## 1. 최종 목표

프로토타입은 아래 end-to-end 흐름을 실제로 재현해야 한다.

1. `mail-mcp@1.0.0`은 검증 후 `VERIFIED` 상태로 실행된다.
2. 정상 서명된 `mail-mcp@1.0.1`의 dummy canary 유출을 탐지한다.
3. 검증자 3명 중 2명의 `FAIL` 판정이 체인에 기록된다.
4. 릴리스 상태가 `REVOKED`로 변경된다.
5. 두 Gateway가 해당 릴리스를 process spawn 전에 차단한다.
6. 전체 흐름을 대시보드와 재현 가능한 데모 명령으로 확인한다.

## 2. 역할과 브랜치

| 역할 | 브랜치/worktree | 소유 영역 | 수정 금지 영역 |
|---|---|---|---|
| Main | `main` | 구조, 인터페이스, 일정, 병합, 통합 테스트 | 담당자의 개별 기능을 대신 구현하지 않는다. |
| Security·AI | `feature/security-ai` | 스캐너, AI 분석, fixture, 샌드박스 증거, 평가 | API, UI, 컨트랙트 내부 |
| Blockchain·Backend | `feature/blockchain-backend` | API, DB, 컨트랙트, validator, indexer | UI, 스캐너 내부 |
| Frontend·Gateway·DevOps | `feature/frontend-gateway-devops` | 대시보드, Gateway, Docker, CI, 데모 자동화 | 컨트랙트, 스캐너, API 내부 |
| Reviewer | 읽기 전용 | 구현 브랜치 리뷰 및 통합 위험 분석 | 모든 코드 수정 및 커밋 |

## 3. 공통 작업 규칙

1. 각 담당자는 자신이 소유한 경로만 수정한다.
2. 공통 인터페이스 변경은 구현 전에 Main의 승인을 받는다.
3. 다른 브랜치의 코드를 임의로 다시 작성하지 않는다.
4. 인터페이스 불일치는 해당 영역 담당자에게 수정 요청한다.
5. 실제 개인정보, 실제 비밀키, 외부 공격 서버를 사용하지 않는다.
6. 악성 fixture는 공개 npm에 배포하지 않고 `demo/fixtures/` 안에서만 사용한다.
7. AI 결과만으로 영구 차단하지 않는다. 결정론적 증거와 검증자 판정을 결합한다.
8. mock, replay, live 결과를 UI와 로그에서 명확하게 구분한다.
9. 모든 기능은 실패 및 timeout 경로를 포함해 테스트한다.
10. 최종 데모에 기여하지 않는 기능은 `Later`로 이동한다.

## 4. 공통 인터페이스 동결

병렬 구현 전에 Main이 아래 항목을 확정하고 `docs/interface-contract.md`에 기록한다.

- `releaseId` 형식
- `artifactDigest` 형식
- `toolSurfaceHash` 형식
- Scan Request/Result JSON Schema
- Finding JSON Schema
- `UNVERIFIED`, `VERIFIED`, `QUARANTINED`, `REVOKED` 상태
- 검증자 판정과 체인 이벤트 형식
- Gateway admission 요청 및 응답 형식
- safe/malicious fixture의 고정 ID와 버전

최소 공통 결과 형식은 다음과 같다.

```json
{
  "releaseId": "mail-mcp@1.0.1",
  "artifactDigest": "sha256:...",
  "toolSurfaceHash": "0x...",
  "scanStatus": "FAILED",
  "findings": [
    {
      "code": "CANARY_EXFILTRATION",
      "severity": "CRITICAL",
      "deterministic": true,
      "evidence": {}
    }
  ],
  "chainStatus": "REVOKED"
}
```

브랜치 간 연결 방향은 다음과 같다.

```text
Security·AI
    └─ ScanResult JSON
          ↓
Blockchain·Backend
    └─ API + DB + Chain Status
          ↓
Frontend·Gateway·DevOps
    └─ Dashboard + ALLOW/BLOCK
```

## 5. Main 규칙

### 역할

전체 구조를 관리하고 세 구현 브랜치의 작업을 조율한다. 직접 기능을 대량 구현하지 않고 인터페이스 확정, 작업 범위 관리, 리뷰 요청, 병합 및 통합 테스트를 담당한다.

### 관리 문서

```text
docs/architecture.md
docs/interface-contract.md
docs/demo-scenario.md
docs/integration-checklist.md
```

### 주요 업무

- 공통 식별자, 상태, JSON Schema 및 이벤트 규격 확정
- 각 브랜치의 소유 경로 위반 여부 확인
- 브랜치 간 의존성 및 변경 요청 관리
- Reviewer 지적사항을 담당 브랜치에 배정
- 병합 후 전체 E2E 테스트 실행
- 최종 데모 시나리오와 fallback 점검

### 병합 순서

1. 공통 타입과 API 계약
2. Blockchain·Backend
3. Security·AI
4. Frontend·Gateway·DevOps
5. 전체 E2E 테스트 및 Reviewer 최종 확인

## 6. Security·AI 규칙

### 담당 범위

- artifact digest 및 tool surface hash 계산
- 정상/악성 버전 diff
- 정적 보안 규칙
- AI semantic analyzer
- AI 프롬프트와 structured JSON 출력
- safe/malicious MCP fixture
- Docker 샌드박스용 탐지 로직
- canary 및 local exfil-sink 테스트
- 탐지 성능 평가 코드

### 필수 Finding

- `SENSITIVE_FILE_READ`
- `UNDECLARED_EGRESS`
- `CANARY_EXFILTRATION`
- `TOOL_SURFACE_CHANGED`
- `SEMANTIC_BEHAVIOR_MISMATCH`

### 수정 가능 경로

```text
services/scanner/
services/exfil-sink/
demo/fixtures/
tests/security/
benchmarks/
```

### 수정 금지 경로

```text
apps/api/
apps/dashboard/
apps/gateway/
contracts/
docker-compose.yml
.github/workflows/
```

### 완료 조건

- safe 1.0.0에서 치명적 finding이 발생하지 않는다.
- malicious 1.0.1에서 dummy canary 유출이 항상 재현된다.
- AI 출력이 Finding JSON Schema를 통과한다.
- AI API가 실패해도 규칙과 샌드박스 결과는 반환된다.
- 테스트 명령과 샘플 결과가 README에 기록되어 있다.

## 7. Blockchain·Backend 규칙

### 담당 범위

- release 등록 및 조회 API
- scan 요청 및 결과 저장 API
- admission check API
- PostgreSQL 데이터 모델과 migration
- `ReleaseRegistry` Solidity 컨트랙트
- 릴리스 상태 머신
- 검증자 3명과 2-of-3 quorum
- 검증자 투표 또는 EIP-712 서명
- 체인 이벤트 수집 indexer
- 로컬 Anvil 및 Base Sepolia 배포 스크립트
- ABI와 TypeScript SDK

### 필수 API

```text
POST /api/releases
POST /api/scans
GET  /api/scans/:scanId
GET  /api/releases/:releaseId
POST /api/validators/vote
POST /api/admission/check
GET  /api/events
```

### 수정 가능 경로

```text
apps/api/
apps/indexer/
apps/validator/
contracts/
packages/contracts-sdk/
packages/protocol/api/
database/
```

### 수정 금지 경로

```text
services/scanner/
demo/fixtures/
apps/dashboard/
apps/gateway/
```

### 완료 조건

- 동일 검증자의 중복 투표를 거부한다.
- 등록되지 않은 검증자의 투표를 거부한다.
- 2개의 `FAIL` 판정 이후 상태가 `REVOKED`로 변경된다.
- 모든 상태 변경에서 체인 이벤트가 발생한다.
- API가 체인 상태를 반영한 admission 응답을 반환한다.
- 컨트랙트 unit test와 API integration test가 통과한다.
- 로컬 체인을 한 명령으로 배포할 수 있다.

## 8. Frontend·Gateway·DevOps 규칙

### 담당 범위

- Next.js 대시보드
- Release Compare 화면
- Scan Pipeline 화면
- Sandbox Timeline 화면
- Validator/Chain 상태 화면
- Agent ALLOW/BLOCK 화면
- MCP stdio Gateway
- 실행 전 admission check
- `REVOKED` 프로세스 spawn 차단
- Docker Compose
- CI와 E2E smoke test
- 데모 reset/run 스크립트
- 공개 데모 페이지 구성

### 수정 가능 경로

```text
apps/dashboard/
apps/gateway/
packages/ui/
docker-compose.yml
.github/workflows/
scripts/demo/
```

### 수정 금지 경로

```text
services/scanner/
contracts/
apps/api/
database/
```

### UI 필수 화면

1. Release Compare
2. Static/AI/Sandbox Scan Progress
3. Sandbox Event Timeline
4. Validator 2-of-3 Progress
5. On-chain Status 및 트랜잭션 링크
6. Agent ALLOW/BLOCK Result

### 완료 조건

- 백엔드가 없어도 mock mode로 UI를 확인할 수 있다.
- 백엔드 연결 시 실제 API 결과를 표시한다.
- Gateway가 safe 1.0.0을 실행한다.
- Gateway가 malicious 1.0.1을 spawn 전에 차단한다.
- `docker compose up`으로 전체 환경을 실행할 수 있다.
- `demo:reset` 후 같은 시나리오를 재현할 수 있다.
- 네트워크 장애 시 명시적인 replay mode를 사용할 수 있다.

## 9. Reviewer 규칙

Reviewer는 코드를 수정하거나 커밋하지 않는다. 구현 브랜치를 읽기 전용으로 검토하고, 문제와 권장 수정 방향만 보고한다.

### 필수 검토 항목

- 요구사항 누락
- 브랜치 간 JSON/API 타입 불일치
- 보안 취약점
- 컨트랙트 상태 전이 오류
- 검증자 중복 투표 및 replay 가능성
- Gateway 우회 가능성
- 악성 fixture가 host에 영향을 줄 가능성
- secret 또는 private key 노출
- UI가 mock 결과를 실제 결과처럼 표시하는지 여부
- Docker 권한 과다
- 실패 및 timeout 테스트 누락
- 데모 실행 순서의 비결정성

### 리뷰 형식

리뷰 결과는 아래 순서로 작성한다.

```text
Critical
High
Medium
Low
Integration Risk
Missing Test
```

각 발견 사항에는 다음을 포함한다.

- 파일과 줄 번호
- 문제가 발생하는 조건
- 실제 영향
- 재현 방법
- 권장 수정 방향

문제가 없다면 `발견된 문제 없음`을 명시하고, 테스트로 완전히 제거할 수 없는 남은 위험을 별도로 기록한다.

## 10. Definition of Done

기능은 다음 조건을 모두 만족해야 완료로 처리한다.

- acceptance test 통과
- 오류 및 timeout 처리
- 필요한 metric과 log 제공
- secret leak test 통과
- README 또는 API 문서 작성
- 담당자가 아닌 팀원의 review 완료
- demo fixture에서 재현 가능
- rollback 또는 disable 방법 제공

## 11. 이번 MVP에서 구현하지 않는 것

- 토큰 발행과 DAO
- 자체 블록체인
- 실제 MCP marketplace
- 임의 npm 패키지 전체 지원
- 모든 remote MCP의 완전한 코드 증명
- Windows, macOS, Linux 완전 호환
- 자체 AI 모델 학습
- 실제 독립기관 validator 네트워크
- Kubernetes, Kafka, multi-region 운영

## 12. 최종 통합 체크리스트

- [ ] 공통 JSON Schema가 모든 서비스에서 동일하다.
- [ ] safe 1.0.0 스캔과 실행이 성공한다.
- [ ] malicious 1.0.1의 signature는 `VALID`로 표시된다.
- [ ] artifact 및 tool surface 변경이 표시된다.
- [ ] dummy canary 유출이 로컬 sink에서 관찰된다.
- [ ] Validator A/B의 FAIL로 2-of-3 quorum이 완성된다.
- [ ] 온체인 상태가 `REVOKED`로 변경된다.
- [ ] 두 Gateway가 process spawn 전에 차단한다.
- [ ] 대시보드에서 전체 이벤트 순서를 확인할 수 있다.
- [ ] live, mock, replay 결과가 명확하게 구분된다.
- [ ] clean reset 후 동일 데모를 10회 연속 재현할 수 있다.
- [ ] 실제 secret이나 개인정보가 저장소와 로그에 없다.
