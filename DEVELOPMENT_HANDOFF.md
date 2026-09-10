# MCPShield 개발 인수인계 — 여기서 시작하세요

기준일: **2026-09-10 KST**. 기능 기준 커밋: **`c9f8798` (`master/main`)**.
이 인수인계 변경은 문서와 미활성 초안 보관이며 기능 수정·브랜치 병합·운영 배포가 아니다.

## 1. 현재 어디까지 만들었나

**전체 마스터 목표 대비 약 70%는 개발 진척의 추정치다.** 요구사항 가중치로 계산한 수치나 테스트 통과율, 운영 배포 완료율이 아니다. 앞으로 할 작업은 완료에 포함하지 않는다.

현재는 **실제 MCP 통신을 사용하는 합성 데이터 데모 + 운영 기능을 확장한 개발본**이다. 전체 마스터 구현과 실제 고객 운영 검증은 미완료다. 첫 실사용 목표는 지원되는 MCP 몇 개를 소규모 팀에 연결해 정상 업무·위험 업데이트 차단·장애 대응을 검증하는 것이다.

| 파트 | Main에 구현된 것 | 남은 핵심 작업 |
|---|---|---|
| Frontend | Next.js/React 대시보드, `/try`, `/console`, 역할별 로그인, 릴리스 검색·등록, 검사·재처리, 정책, 증거·이력, 이의제기 종결, 체인·receipt 표시 | 재검사 UI 작업 브랜치 통합, 쉬운 오류 문구 통일, 실제 브라우저 조작·시각 검증 |
| Backend | Fastify/TypeScript, 기존 `/api`와 확장 `/v1`, tenant 격리, admin/operator/reader, SQLite/PostgreSQL control store, SQL queue·lease·backoff·DLQ, 멱등성, 암호화 증거, 감사 이벤트, chain outbox | 워커 비정상 종료 이력 수정 통합, 종합 health, 실제 운영 DB·secret 관리·복구·부하 검증 |
| Security·AI | npm/tarball/OCI 수집, 정확한 digest·도구 표면 고정, 정적 규칙·변경점·SBOM/취약점 검사, Docker 격리·canary, 증거 Merkle root, AI analyzer/critic·구조화 JSON 코드 | 최신 OCI 전체 검사 실패 해결, 제한된 정보만 AI에 전송하는 정책 연결, 실제 외부 모델 호출·품질 평가 |
| Blockchain | Solidity V1/V2·receipt anchor, EIP-712, 2-of-3, 중복·만료·다른 체인 서명 거부, 격리·terminal 폐기, 정책 버전, indexer·reorg/전송 복구 | Base Sepolia 배포·외부 RPC 검증, 독립 기관 validator, 운영 키 관리 |
| Gateway | 실제 stdio/HTTP MCP, 실행 전 차단, 매 도구 호출 승인 재검사, identity·policy·expiry 검증, signed cache·장애 fallback, 제한된 npm/OCI 실행 프로필 | 최신 OCI 전체 흐름 통과, 지원 대상 확대, 후속 호출 없는 지속 실행의 폐기 즉시 중단 보장 |
| DevOps·관측 | Compose, GitHub Actions, 테스트·빌드·secret/image 검사, 이미지 서명 절차, OTel trace/metric, Prometheus/Grafana·알림 규칙, 복원 절차 | 최신 전체 CI 성공·서명 이미지·공개 배포, 실제 알림 수신자, 운영 collector·백업·부하 검증 |

명확한 미완료 사항:

- `/health`는 현재 기본 `status`와 원장 모드를 반환한다. API/DB/체인/스캐너의 종합 readiness가 아니다.
- 오류 표시 영역은 있지만 일부 응답은 `FORBIDDEN` 같은 내부 코드다. 사용자용 한 줄 설명 통일이 남았다.
- 감사 이벤트 저장과 일부 불변 이의제기/receipt 처리는 있다. 모든 감사 로그를 DB 관리자도 변경하지 못하는 보관 체계는 미완료다.
- 외부 AI, 실제 Gmail/CRM 계정, 테스트넷, 실제 S3/KMS, 외부 알림 수신자는 clone만으로 구성되지 않는다.
- Redis/Kafka/RabbitMQ/Nginx는 현재 필수 의존성이 아니다. SQL 큐·기존 캐시로 시작하고 측정된 요구에 따라 도입한다.

## 2. 반드시 올바른 브랜치로 받기

저장소: <https://github.com/sihoon-0077/MCPShield>

**GitHub 기본 브랜치는 `main`이지만 최신 통합 개발본은 `master/main`이다.** 기본 clone 후 보이는 예전 코드로 개발을 시작하지 말 것.

```sh
git clone --branch master/main https://github.com/sihoon-0077/MCPShield.git
cd MCPShield
git status --short
git log -1 --oneline
```

이미 clone했다면 작업 중 변경을 보존한 상태에서 `git fetch origin` 후 브랜치를 선택한다. 기존 변경을 강제로 초기화하지 않는다.

| 브랜치 | 인수인계 시 기능 HEAD | 용도 |
|---|---|---|
| `master/main` | `c9f8798` + 인수인계 문서 커밋 | 새 작업의 기본 출발점 |
| `master/backend-appeals` | `9217faf` | 워커가 사라져 재시도 한도를 소진할 때 원본 이의제기 실패 이력을 원자적으로 남기는 후속 변경 |
| `master/frontend-appeals` | `859e727` | 공통 검사 요청 폼, 이의제기와 새 검사 연결 UI |
| `master/security-ai` | `e46c3ed` | 별도 v2 정보 공개 정책을 정확히 고정하고 기존 v1 증거로 승인하지 않는 후속 변경 |
| `mcp/main` | `6aa3702` | 보존한 기존 MCP 데모 기준점 |
| `main` | `0831a55` | 이전 기본 브랜치. 최신 master 통합본 아님 |

파트 브랜치는 **통합 대기 작업 보관본**이지 각각 최신 Main의 상위 버전이 아니다. 이미 Main에 다른 SHA로 cherry-pick된 변경이 많다. `git log main..branch`의 모든 커밋을 신규 작업으로 세거나 브랜치 전체를 무검토 병합하지 않는다.

후속 작업 후보와 비교 경로:

- Backend `9217faf`: `apps/api/src/control-store.ts`, `tests/api/appeals.test.ts`.
- Frontend `859e727`: `apps/dashboard/components/scan-request-form.tsx`, `appeal-records.tsx`, `operations-console.tsx`, `release-workflow.tsx`.
- Security `e46c3ed`: `services/scanner/src/scoped-policy.mjs`, prepared/OCI binding·policy와 해당 테스트.

각 후보는 현재 Main과 diff를 보고 의존성·테스트를 확인한 뒤 작은 단위로 통합한다. 이번 인수인계에서 이 변경들의 통합 성공을 주장하지 않는다.

## 3. 다음 개발자의 첫 실행

### 준비

- Node.js **24.x 권장**, 프로젝트 지원 범위는 `>=22 <25`다. 이번 개발 PC는 `v24.13.0`이다.
- Git와 npm. Windows PowerShell에서 실행 정책이 걸리면 아래 `npm`을 `npm.cmd`로 실행한다.
- 실제 격리 검사는 **Linux Docker** 환경이 필요하다. Windows의 Docker 미실행/skip을 통과로 집계하지 않는다.
- 아래 명령은 모두 저장소 루트에서 실행한다.

```sh
npm ci
npm run build:backend
npm run demo:live-smoke
```

`demo:live-smoke`는 임시 API와 합성 fixture의 등록·검사 결과·검증 서명·Gateway 실행/차단을 검사한 뒤 종료한다. 화면을 계속 띄우는 명령이 아니다. 실제 고객 데이터나 테스트넷을 사용하지 않는다.

### Docker 없이 웹과 운영 콘솔 보기

```sh
node scripts/ops/init-control.mjs
```

이 명령은 새 `.env.master.local`에 로컬 전용 토큰·암호화 키를 생성한다. 파일이 이미 있으면 덮어쓰지 않는다. 파일을 Git·채팅·스크린샷에 공유하지 말고 자신의 편집기에서만 확인한다. `CONTROL_PLANE_CREDENTIALS`의 해당 역할 토큰으로 로그인한다.

저장소 루트에서 **세 터미널을 열어 유지**한다.

터미널 A — API:

```sh
node --env-file=.env.master.local --import tsx apps/api/src/server.ts
```

터미널 B — 검사 Worker:

```sh
node --env-file=.env.master.local --import tsx apps/api/src/control-worker-cli.ts
```

터미널 C — 웹:

```sh
node --env-file=.env.master.local node_modules/next/dist/bin/next dev apps/dashboard --hostname 127.0.0.1 --port 3300
```

브라우저는 **<http://127.0.0.1:3300> 한 주소**에서 시작한다.

| 경로 | 내용 |
|---|---|
| `/` | 대시보드 |
| `/try` | 설치 없는 합성 데이터 체험 |
| `/console` | 운영 콘솔, 역할 토큰 로그인 |

API 기본 연결 확인은 `http://127.0.0.1:3301/health`다. 위 명령은 별도 HTTP MCP Gateway를 시작하지 않으므로 `3300/mcp`가 생기는 것은 아니다. Gateway 실행은 [Gateway 가이드](apps/gateway/README.md)를 따른다.

로컬 운영 콘솔의 기본 검사는 정적 전용이며 `INCONCLUSIVE`/`ABSTAIN`이 정상적인 결과일 수 있다. 공개 체험의 고정 fixture 성공과 임의 패키지의 안전 승인을 혼동하지 않는다. `.env.master.local` 기본 control DB는 `data/control-plane.sqlite`로 보존되고 기존 `/api` 데모 DB는 메모리다.

연결 거부가 나오면 먼저 A/C 터미널의 종료·오류와 포트를 확인한다. 주소만 안내했다고 서버가 실행되는 것은 아니다. Windows 확인 명령:

```powershell
Get-NetTCPConnection -State Listen -LocalPort 3300,3301
Invoke-RestMethod http://127.0.0.1:3301/health
```

### Linux Docker / PostgreSQL

```sh
docker compose --env-file .env.master.local -f docker-compose.yml -f compose.control.yml up --build --wait
```

이 구성의 콘솔은 `http://127.0.0.1:3000/console`이다. 이때 로컬 A/B/C 실행과 혼용하지 말고 해당 구성의 환경변수·포트를 따른다. Compose control worker도 기본 정적 전용이다. 실제 동적 검사는 별도 신뢰된 Linux worker에 Docker·고정 builder/image·검사 정책·비공개 저장소를 설정해야 한다. 상세: [운영 가이드](docs/operations-runbook.md).

## 4. 코드와 처리 흐름

```text
운영자 → Next.js /console → 같은 출처 BFF /api/control → Fastify /v1
  → 권한·입력·중복 확인 → DB 작업 큐
  → Worker → Resolver / Static / AI / Docker Sandbox
  → 암호화 증거 + reportRoot + PASS/FAIL/ABSTAIN
  → 독립 재검사 validator → EIP-712 서명 → chain outbox → V2 컨트랙트
  → Indexer/복구 → DB 상태·화면 갱신

AI의 도구 호출 → Gateway → 최신 실행 허가 확인
  → ALLOW: 고정된 MCP 실행·결과 반환
  → BLOCK 또는 승인 확인 실패: 실행/전달 차단
```

- 검사는 등록/업데이트/재검사 시점의 무거운 작업이다. 매 도구 호출에서는 승인·정확한 파일·정책·유효기간을 재확인한다.
- `COMPLETED`는 작업 완료, `READY`는 증거 준비, `PASS`는 검사 판정이다. 어느 하나만으로 실행 허가가 되지 않는다.
- DB와 체인은 하나의 원자적 트랜잭션이 아니다. DB outbox에 제출 작업을 보존하고 체인 전송·확인·재편성을 복구한다.
- AI 단독 판단으로 영구 폐기하지 않는다. 근거 부족은 ABSTAIN이며, 설정 누락을 PASS로 바꾸지 않는다.

| 위치 | 책임 |
|---|---|
| `apps/dashboard` | 공개 화면·운영 콘솔·인증된 BFF |
| `apps/api`, `database/migrations` | API·권한·SQL queue·evidence·outbox·migration |
| `services/resolver`, `services/scanner`, `services/exfil-sink` | 수집·분석·격리 관찰·합성 유출 수신 |
| `apps/validator`, `contracts`, `packages/contracts-sdk` | 독립 재검사·서명·컨트랙트·체인 통신 |
| `apps/indexer`, `apps/reconciler` | 체인 상태 투영·미확정 전송·reorg 복구 |
| `apps/gateway` | 실제 MCP 프로토콜·실행 통제·서명 캐시 |
| `packages/telemetry`, `deploy/observability` | trace·metric·관측 설정 |

## 5. 검증 결과와 알려진 실패

### 마지막 기능 커밋의 원격 검사

[CI 34286988002 — c9f8798](https://github.com/sihoon-0077/MCPShield/actions/runs/34286988002)를 2026-09-10 GitHub API로 확인했다.

- PostgreSQL job: 성공.
- Node 24 job: 성공.
- Node 22 job: **실패**, 아래 세 단계.
  1. `Exercise composed OCI inventory, Trivy, local semantic contract and MCP observations`
  2. `Independently rescan supported OCI safe and canary fixtures with native package evidence`
  3. `Exercise native OCI worker and independent single-key validators through V2 and both Gateways`
- repeat-demo와 signed-image: 이번 run에서는 skipped. 최신 서명 이미지 생성/배포 성공 증거 없음.

이전 기록에는 private Trivy 산출물 미생성과 `OCI_UNSUPPORTED_FILESYSTEM_ENTRY`에 따른 ABSTAIN이 있다. **최신 실패의 원인을 추측으로 확정하지 말고 위 run의 단계별 진단을 확인한다.** 지원하지 않는 입력을 허용으로 바꾸거나 보안 gate를 건너뛰어 해결하지 않는다.

### 로컬에서 확인한 범위

2026-09-10 같은 기능 커밋에서 `npm run build:backend` 성공. 아래 focused 검사는 **15 PASS / 1 PostgreSQL 선택 SKIP / 0 FAIL**였다. 인수인계 작성 중 `npm run demo:live-smoke`도 다시 실행해 **정상 ALLOW / 악성 BLOCK_BEFORE_SPAWN / 종료 코드 0**을 확인했다. 전체 테스트 재실행이나 실제 Linux 검사 결과는 아니다.

```sh
node --import tsx --test tests/api/appeals.test.ts apps/dashboard/test/appeals-integration.test.mts tests/integration/release-readiness.test.ts
```

변경 후 기본 검증:

```sh
npm run build
npm test
```

위 명령의 환경별 skip은 별도 보고한다. Linux 전용 검사에 필요한 환경변수/정확한 명령은 [.github/workflows/frontend-gateway-devops.yml](.github/workflows/frontend-gateway-devops.yml)에 있다. 전체 `npm test` 성공만으로 선택적 Docker·외부 AI 검증까지 성공했다고 하지 않는다.

성능/탐지의 알려진 경계:

- 정적 metadata 평가: [485개 중 126개 탐지, 약 25.98%](benchmarks/results/mcptox-static-2026-09-09.json). 전체 방어 탐지율·실제 모델 품질·정상 표본 오탐률이 아니다.
- 1만 identity 부하 실험: [PARTIAL_FAILED](benchmarks/results/admission-matrix-10000-2026-09-09.json). 79,000 요청 완료는 전체 성공이 아니다. 원인 재현과 작은 표본부터 시작한다.
- 과거 커밋의 Linux/서명 이미지 성공 증거는 [요구사항 추적표](docs/master-implementation-plan.md)에 있다. 최신 SHA의 성공으로 재사용하지 않는다.

## 6. 다음 작업 순서와 완료 조건

| 순서 | 할 일 | 완료를 판단할 증거 |
|---|---|---|
| P0 | 위 OCI 실패 세 단계 재현·수정 | 지원 정상 fixture PASS, 악성 fixture FAIL, 독립 validator 정족수, 두 Gateway에서 폐기 이미지 실행 0건, 같은 SHA의 Linux CI 성공 |
| P0 | Backend/Frontend/Security 후속 커밋 검토·통합 | Main에서 관련 회귀·build 성공, PostgreSQL worker-lost/동시성, BFF·실제 브라우저 재검사 흐름, v1/v2 증거 혼용 거부 |
| P1 | 쉬운 오류 설명·종합 health·실제 장애 알림 | 입력/인증/권한/충돌별 안내, DB/RPC/worker 장애 주입 반영, 설정된 수신자의 실제 알림 확인 |
| P1 | 외부 AI를 제한된 정보 공개 정책에 연결 | 실제 모델 호출, 원문/secret 전송 제한, analyzer·critic·probe 전 경로 일관성, 실패 시 ABSTAIN, 비용·탐지/오탐 평가 |
| P1 | 테스트넷·실제 저장소·키/백업 운영 | 배포 주소·tx·chain ID·explorer, 실제 암호화 증거 저장/조회, 별도 DB 복원과 복구 시간 측정 |
| P2 | 지원 MCP 실사용·부하·배포 | 실제 정상 업무와 악성 업데이트 차단, 명시한 동시성·대기시간 목표 검증, 같은 SHA의 release image·보안 검사·배포 smoke |

외부 자원/비용/계정이 필요한 작업은 소유자와 설정을 확인한다. 실제 키는 server secret으로 주입하며 문서나 browser 입력으로 수집하지 않는다. 원본 공개 데모를 새 운영 시스템으로 자동 덮어쓰지 않는다.

## 7. 로그·배포·자동화

- 업무 기록: `/console`의 검사 작업·상세·릴리스 이력. API는 `/v1/events`, `/v1/releases/:releaseId/history`, `/v1/scans/:scanId`.
- 프로세스 로그: API/Worker/Gateway stdout의 JSON과 trace ID. 원문 메일·토큰·증거 내용을 로그에 추가하지 않는다.
- 관측 overlay를 실행한 경우 Prometheus `http://127.0.0.1:9090`, Grafana `http://127.0.0.1:3100/d/mcpshield-operations`. 실제 수신자 설정 없이 알림 전달 완료라고 하지 않는다.
- 기존 공개 체험: <https://mcpshield-judge-lab-production.up.railway.app/try>
- 기존 공개 MCP: <https://mcpshield-judge-lab-production.up.railway.app/mcp>
- 위 공개 주소는 기존 합성 데모다. master/main의 최신 기능이 배포됐다는 뜻이 아니며, 이 인수인계 작업은 Railway 배포를 하지 않는다.
- 활성 CI 구성은 `.github/workflows/frontend-gateway-devops.yml`이다. `master/main` push는 검사를 시작할 수 있지만 검사 통과나 배포 성공을 뜻하지 않는다.
- Backend 작업 공간의 미추적 `ci.yml`/`healthcheck.yml`은 [자동화 초안 보관 문서](docs/handoff-automation-drafts.md)에 보존했다. `.github/workflows`에 추가하지 않았으며 중복 CI·예약 실행·외부 webhook 발송을 활성화하지 않았다.

## 8. 다음 담당자가 읽을 문서

1. [AGENTS.md](AGENTS.md), [협업 규칙](WORKTREE_COLLABORATION_RULES.md): Main 승인·코드 소유권·보안 경계. 오래된 feature 브랜치명은 역사적 기록이며 현재 브랜치는 이 문서 2절을 따른다.
2. [전체 요구사항 추적표](docs/master-implementation-plan.md): 요구사항 ID별 구현과 검증 이력.
3. [운영 가이드](docs/operations-runbook.md): 환경 구성, worker, 비공개 이미지, 로그, 장애, 복원.
4. [API](apps/api/README.md), [Dashboard](apps/dashboard/README.md), [Gateway](apps/gateway/README.md): 각 서비스 사용법. API README의 초기 SQLite-only 설명은 기존 `/api` MVP이고, 뒤의 `/v1` control plane은 PostgreSQL adapter를 포함한다.
5. [아키텍처](docs/architecture.md), [인터페이스](docs/interface-contract.md), [보안 정책](SECURITY.md).

원본 마스터 문서는 저장소 밖에서 전달된 자료이며 이 인수인계에 새로 복사하지 않았다. 추적표에 원본 파일명과 SHA-256이 있다. 원문 조항 대조가 필요하면 소유자에게 그 원본을 받아 hash를 확인한다. 기존 MVP 체크리스트의 체크 여부보다 최신 추적표·해당 SHA의 실제 검증 증거를 우선한다.

### 새 작업 브랜치 예시

```sh
git fetch origin
git worktree add -b work/backend-next ../MCPShield-backend-next origin/master/main
git worktree add -b work/frontend-next ../MCPShield-frontend-next origin/master/main
git worktree add -b work/security-next ../MCPShield-security-next origin/master/main
```

위 브랜치명/폴더는 신규 이름 예시다. 이미 있으면 덮어쓰지 말고 기존 작업을 확인한다. 과거 worktree의 `.git` 파일을 복사하지 않는다. 코드·설정·문서에서 MOCK/REPLAY/LIVE/LOCAL_CONTRACT_TEST 경계를 유지하고, 변경별 테스트 결과와 미검증 항목을 인수인계에 이어 기록한다.
