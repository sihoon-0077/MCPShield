# MCPShield 개발 인수인계 — 여기서 시작하세요

기준일: **2026-09-19 KST**. 기능 통합 기준: **`1686547` (`master/main`)** 및 후속 검증·문서 보완.
9월 10일 이후 보안·백엔드·프론트엔드 후속 변경과 종합 상태 점검을 통합했다. 최신 전체 Linux Docker 검증과 공개 배포는 아직 완료되지 않았다.

## 1. 현재 어디까지 만들었나

**전체 마스터 목표 대비 약 70%는 개발 진척의 추정치다.** 요구사항 가중치로 계산한 수치나 테스트 통과율, 운영 배포 완료율이 아니다. 앞으로 할 작업은 완료에 포함하지 않는다.

현재는 **실제 MCP 통신을 사용하는 합성 데이터 데모 + 운영 기능을 확장한 개발본**이다. 전체 마스터 구현과 실제 고객 운영 검증은 미완료다. 첫 실사용 목표는 지원되는 MCP 몇 개를 소규모 팀에 연결해 정상 업무·위험 업데이트 차단·장애 대응을 검증하는 것이다.

| 파트 | Main에 구현된 것 | 남은 핵심 작업 |
|---|---|---|
| Frontend | Next.js/React 대시보드, `/try`, `/console`, 역할별 로그인, 릴리스 검색·등록, 검사·재처리, 정책, 증거·이력, 이의제기 종결·변경본 재검사 연결, 체인·receipt 표시, 공통 한국어 오류 안내 | 실제 브라우저 조작·시각 검증, 실제 운영 사용자 검증 |
| Backend | Fastify/TypeScript, 기존 `/api`와 확장 `/v1`, tenant 격리, admin/operator/reader, SQLite/PostgreSQL, SQL queue·lease·backoff·DLQ, 멱등성, 암호화 증거·감사 이벤트·chain outbox, scan/preparation 시도별 lease fence, 인증된 종합 health·실제 Worker heartbeat | scoped-v2 원본 catalogue·독립 validator 연결 통합, 실제 운영 DB·secret 관리·복구·부하 검증 |
| Security·AI | npm/tarball/OCI 수집, 정확한 digest·도구 표면 고정, 정적 규칙·변경점·SBOM/취약점 검사, Docker 격리·canary, 증거 Merkle root, Node scoped-v2의 제한 DTO·독립 critic·생성 probe 인자 연결 | 새 scoped-v2 전체 Linux 검증, OCI scoped-v2 연결, 실제 외부 모델 호출·품질 평가 |
| Blockchain | Solidity V1/V2·receipt anchor, EIP-712, 2-of-3, 중복·만료·다른 체인 서명 거부, 격리·terminal 폐기, 정책 버전, indexer·reorg/전송 복구 | Base Sepolia 배포·외부 RPC 검증, 독립 기관 validator, 운영 키 관리 |
| Gateway | 실제 stdio/HTTP MCP, 실행 전 차단, 매 도구 호출 승인 재검사, identity·policy·expiry 검증, signed cache·장애 fallback, 제한된 npm/OCI 실행 프로필, v1/local-v2/provider-v2 identity 분리 회귀 | 새 scoped-v2 Linux 연결, 지원 대상 확대, 후속 호출 없는 지속 실행의 폐기 즉시 중단 보장 |
| DevOps·관측 | Compose, GitHub Actions, 테스트·빌드·secret/image 검사, 이미지 서명 절차, OTel trace/metric, Prometheus/Grafana·알림 규칙, 복원 절차 | 최신 전체 CI 성공·서명 이미지·공개 배포, 실제 알림 수신자, 운영 collector·백업·부하 검증 |

명확한 미완료 사항:

- `/health`는 기본 liveness로 유지한다. 인증된 `/v1/health`와 `/console`의 별도 상태 패널이 API/DB/체인/스캐너 readiness를 확인한다. 정적 전용 Worker는 LIMITED, 실제 관측이 없으면 UNKNOWN이다. READY는 실행 허가·전체 스캔 성공이 아니다.
- 공통 control client는 400/401/403/409 등과 이의제기 오류에 한국어 안내를 표시하고 코드를 함께 보존한다. 네트워크 응답 유실 시 자동 재전송하지 않고 기록 재확인을 안내한다. 모든 운영 오류의 UX 검증이 끝났다는 뜻은 아니다.
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
| `master/main` | `1686547` + 후속 검증·문서 | 새 작업의 기본 출발점. 로컬 변경은 push 전까지 원격과 다름 |
| `master/backend-appeals` | `7da231f` | preparation fence·종합 API·heartbeat는 Main `970cc67`/`9f88d6d`로 통합 |
| `master/frontend-appeals` | `5225030` | health UI는 Main `92c15bd`; 후속 원문 오류 정제는 Main 별도 보완 |
| `master/security-health` | `433c903` | Main `d683b5b`로 체인 가용성 probe 통합. 이전 security-ai는 보존 |
| `master/gateway-pagination` | `303870c` | Main `9a2a832`로 SDK 합산/실제 wire pagination 검사 수정 |
| `mcp/main` | `6aa3702` | 보존한 기존 MCP 데모 기준점 |
| `main` | `0831a55` | 이전 기본 브랜치. 최신 master 통합본 아님 |

파트 브랜치는 각각 최신 Main의 상위 버전이 아니다. 이미 Main에 다른 SHA로 cherry-pick된 변경이 많다. `git log main..branch`의 모든 커밋을 신규 작업으로 세거나 브랜치 전체를 무검토 병합하지 않는다.

이번 통합의 주요 비교 경로:

- Backend `9217faf`: `apps/api/src/control-store.ts`, `tests/api/appeals.test.ts`.
- Frontend `859e727`: `apps/dashboard/components/scan-request-form.tsx`, `appeal-records.tsx`, `operations-console.tsx`, `release-workflow.tsx`.
- Security `e46c3ed`: `services/scanner/src/scoped-policy.mjs`, prepared/OCI binding·policy와 해당 테스트.

Main은 `365efcf`에서 v1 증거를 재해시해 v2 승인으로 재사용하는 경로를 검사하고, `809f7e2`에서 stale attempt 회귀를 PostgreSQL gate에도 연결했다. `ee4d908`/`db9e28b`는 Node scoped-v2 scanner·UI·Gateway 경계를 추가했다. 실제 외부 AI 호출·품질 및 새 API/validator 전체 실행 증거는 별도다.

## 3. 다음 개발자의 첫 실행

### 사용자 지정 구현 중단 조건 (2026-09-19)

계정 주간 잔여 한도가 **50% 이하**가 되면 진행 중인 bounded 작업만 안전하게 마무리한다.
새 기능은 시작하지 않고, 원본 마스터 문서 전체의 `완료 / 부분 / 미완료` 재감사와 MD 보고를
수행한다. 감사 후 사용자 재개 요청 없이 자동으로 신규 구현을 확장하지 않는다.
한도는 계정 공용 실제 usage 도구로 확인하며 기존 70% 추정치를 요구사항 완료율로 재사용하지 않는다.

Node scoped-v2 API/worker·독립 validator는 `e55c1ab`에 통합됐다. 기존 v1 설정은 바꾸지 않고,
별도 원본 허가 catalogue와 검사 설정을 준비해야 한다. 설정·철회·롤백 및 실제 Linux 명령은
[API README의 Additive Node scoped v2](apps/api/README.md#additive-node-scoped-v2)를 따른다.
정책의 `PROVIDER_EXECUTION` 표시는 실제 외부 AI 호출 성공이나 품질을 의미하지 않는다.

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

### 최신 원격 결과와 수정 상태

[CI 35425746994 — 0351567](https://github.com/sihoon-0077/MCPShield/actions/runs/35425746994)는 종료·전체 실패다.
PostgreSQL 40 PASS/1 native Docker SKIP, Node 24, 10회 반복 데모는 성공했다.
Node 22의 기존 OCI worker→독립 single-key validator→V2→두 Gateway는 **2 PASS/0 SKIP**,
prepared npm 전체 흐름은 **3 PASS/0 SKIP**다. 과거 SDK cursor 단언 실패는 해결됐다.
남은 실패는 Compose dashboard 빌드에서 공유 `scoped-policy.mjs`를 못 찾은 것이다.
Main `b9f591a`는 Docker COPY와 client-safe serializer를 고쳤으며 로컬 build/import closure 검사가 통과했다.
이 수정과 새 scoped-v2 통합본의 후속 Linux 실행은 별도로 확인해야 한다.
signed-image job은 이미지 실행·취약점 검사·SBOM까지만 성공했고 provenance/SBOM 서명·검증·artifact
보관 단계는 상위 verify 실패로 skipped였다. 아래 기록은 이전 실패의 원인이며 현재 실패 목록이 아니다.

[CI 34439175673 — f957451](https://github.com/sihoon-0077/MCPShield/actions/runs/34439175673)를 2026-09-19 GitHub API와 실제 job 로그로 확인했다. 아래는 수정 전 결과이며 새 통합본 성공 증거가 아니다.

- PostgreSQL job: 성공.
- Node 24 job: 성공.
- Node 22 job: **실패**, 아래 세 단계.
  1. `Exercise composed OCI inventory, Trivy, local semantic contract and MCP observations`
  2. `Independently rescan supported OCI safe and canary fixtures with native package evidence`
  3. `Exercise native OCI worker and independent single-key validators through V2 and both Gateways`
- repeat-demo와 signed-image: 이번 run에서는 skipped. 최신 서명 이미지 생성/배포 성공 증거 없음.

실제 진단: 지원 정상 fixture는 승인 base와 일치하는 527개 `Directory`의 mode `02755` 때문에 `SET_ID_BITS`로 보류됐다. `8155bb0`은 후보가 없는 trusted builder 생성 단계에서만 `/usr/local`, `/home/node` 디렉터리의 set-ID 비트를 제거한다. 후보 검사 규칙과 base 일치 검사는 유지한다. 별도 composed 검사는 패키지 없는 Trivy 보고서가 `Results`를 생략해 실패했다. 생략을 빈 원본 증거로 보존하되 `INCONCLUSIVE / OCI_TRIVY_PACKAGE_COVERAGE_INCOMPLETE`로 처리한다. 정상 지원 프로필 PASS, 악성 FAIL 및 독립 validator→Gateway 전체 경로는 새 Linux CI에서 재확인해야 한다.

### 로컬에서 확인한 범위

`e55c1ab`에서 전체 `npm test` 종료 0과 `npm run build`(기본 Next Turbopack 포함)가 성공했다.
이는 원격 Docker/PostgreSQL gate의 대체가 아니다. Node scoped API/validator 집중 회귀는
7 PASS/0 SKIP이며 Docker 관찰은 명시적으로 synthetic이다. Frontend 교차 리뷰로
`chainUnavailable` 보존과 mode 불일치 409/queue·appeal slot 미소비를 실제 API에서 재확인했다.
후속 `1686547`은 고정 한국어 안내 외 원문 오류·unknown code 반사를 막고, 관련 client/BFF 및
release gate 14 PASS/0 SKIP와 backend 타입 검사를 통과했다. 자동 재전송은 추가하지 않았다.
2026-09-19 생산 의존성 `npm audit --omit=dev --audit-level=high` 결과 0 vulnerabilities.

최신 통합 `9a2a832` + readiness 보완에서 전체 `npm test` 종료 0, backend+Next build 성공.
상태 API/BFF/CLI focused 8 PASS/0 SKIP는 실제 SQLite·로컬 EVM·정적 Worker의 상태와 RPC/Worker
종료, tenant 분리 및 명령행 종료 코드까지 확인한다. dashboard 37 PASS/1 조건부 HTTP SKIP.
Linux Docker·실제 새 PostgreSQL heartbeat·실제 브라우저 클릭 검증을 대신하지 않는다.
사용법과 종료 코드 0/1/2는 [운영 가이드의 종합 준비 상태](docs/operations-runbook.md#종합-준비-상태와-단발-점검)를 따른다.

2026-09-19 `8155bb0`의 전체 `npm test` 성공: backend 112 PASS/8 SKIP, security·Gateway·기존 dashboard·replay·실제 stdio·합성 LIVE smoke 완료. 이후 UI 통합본 `2a26c6d`에서 dashboard 32 PASS/1 조건부 HTTP SKIP와 `npm run build` 성공. `809f7e2`의 control-plane 회귀는 12 PASS/2 PostgreSQL SKIP. Linux Docker·실제 PostgreSQL·외부 AI 실행 증거는 아니다.

추가 통합 검사: scoped/binding 15 PASS, v1/v2 정책 격리 6 PASS, Backend/API/BFF 34 PASS/4 PostgreSQL SKIP, OCI 18 PASS/6 native SKIP. 두 담당자의 읽기 전용 교차 리뷰에서 조치할 회귀는 발견되지 않았다. 실제 브라우저 폼의 클릭·연속 제출·응답 유실 시 hook 상태 유지는 별도 QA가 남았다.

빌드 뒤 `MCPSHIELD_FORM_HTTP_TESTS=1 node --import tsx --test apps/dashboard/test/forms.test.mts`도 3 PASS/0 SKIP로 재확인했다. 실제 Next HTTP의 native POST/CSRF/비밀값 비반사 검사이며 브라우저 hydration QA의 대체 증거는 아니다.

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
| P0 | 수정된 Compose와 새 scoped Node v2 전체 Linux 검증 | 기존 OCI/npm 회귀 유지, scoped-v2 원본 확인·독립 validator 정족수·두 Gateway, Compose·Grafana·서명 이미지까지 같은 SHA 성공 |
| P0 | 통합본의 실제 PostgreSQL·브라우저 검증 | 기존 PG worker-lost/동시성/heartbeat native 성공 유지, scoped mode 오류의 무변경 거부와 실제 브라우저 재검사·응답 유실 처리 |
| P1 | 종합 health 운영 검증·실제 장애 알림 | API/Worker/RPC·BFF·단발 CLI와 PG/Docker readiness 검증 있음. 설정된 수신자의 실제 알림 확인은 남음. |
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
