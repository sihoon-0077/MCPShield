# MCPShield 마스터 문서 구현 현황

기준일: 2026-09-09 KST. 상태: **구현 진행 중 — 전체 완료 아님**.

기준 문서: 사용자가 제공한 `MCPShield_전체_시스템디자인_해커톤_마스터문서.md`.
원본 SHA-256: `702268984174af450276b5292a4afccd6a4d5dce79738fe3abde41c4d30d4ea2`.
시작 커밋: `6aa370285154f683989f2bf9b219bd2c052e6cee` (`mcp/main`).
기존 코드·공개 데모를 보존하고 `master/main`에서 통합한다.

## 최신 통합 체크포인트 (2026-09-09 KST)

아래 기록이 이전 커밋의 진행 중 표기보다 우선한다. 대화에서 설명한 약 70%는
가중 요구사항별로 계산한 완료율이 아닌 구현 진척 추정치였다. 이를 검증 완료율이나
공개 배포 완료율로 사용하지 않는다. 전체 목표는 아직 완료되지 않았다.

- `624b702`·`b598271`·`a10b75d`: 누락된 npm lock을 격리된 native npm과
  메타데이터 전용 broker로 생성하고 기존 SRI 검증·오프라인 설치·전체 스캔에 연결.
  원본 identity 불변, 후보 코드·설치 스크립트 미실행. 새 builder CID의 Linux 실측은 대기.
- `457a91d`·`42ba032`·`5dc97c4`: prepared worker의 엄격한 정책·실제 로컬 이미지
  재확인, 검증자의 독립 재스캔 및 키 하나만 보유하는 CLI 통합. Linux 전용 전체 회귀는
  worker 2회 + 별도 검증자 프로세스 4회 + V2 정족수 + 두 Gateway 차단을 검사한다.
  AI 응답은 명시적 루프백 stub이며 외부 기관 참여나 상용 모델 품질 검증이 아니다.
- `29071a9`: 준비 작업·원본/파생 release·운영자 구성 다운로드·증거 요약·SSE 재조회 UI 통합.
  통합 후 대시보드 21개 중 1개 테스트가 새 backend 검증 규칙과 불일치해 실패했다.
  `821f594`에서 production gate를 유지하고 명시적 synthetic 테스트 계약을 보완했다.
  5MiB 이상의 실제 암호화 증거를 두 경로에서 요약하고 원문을 노출하지 않는 검사 포함 23개 통과.
- `d77fbec`: Linux CI에 실제 prepared 전체 회귀를 추가. 기존 공식 MCP client를
  운영 의존성으로 이동했으며 버전 변경이나 새 라이브러리 도입은 없다.
- `821f594`의 로컬 전체 `npm test` 성공: backend 71개 통과·4개 외부 환경 명시 skip,
  Security 78개 통과·Docker 10개 skip, Gateway 67개 통과·Docker 1개 skip, dashboard 23개 통과,
  replay·MCP E2E·live smoke 모두 성공. 타입 검사와 Next production build도 통과했다.
  이후 PostgreSQL 수정 `3285714`는 로컬 타입 검사 통과, 실제 DB 회귀는 아래 CI에서 확인한다.
  Windows에서 실제 Docker·PostgreSQL 통과를 주장하지 않는다.
- 추가 로컬 보안 78개 통과·Docker 10개 skip, Gateway 66개 통과·Docker 1개 skip,
  운영 의존성 audit 0건. `de4fc9f`는 파일 I/O 중 만료 재검사까지 포함해 서명·경합
  회귀 12개 통과. 코드별 테스트 개수를 합쳐 제품 안전성이나 탐지율로 해석하지 않는다.
- Gateway terminal revocation은 release/chain/registry 범위로 정책·tenant 변경을 넘어 유지한다.
  임시 캐시 쓰기 및 비동기 lock 정리 중 오래된 ALLOW가 반환되는 경합을 발견했다.
  Main 수정과 별도 프로세스 barrier 회귀 `2f1e03e`를 함께 실행해 11개 테스트 통과.
  두 경합 모두 차단·캐시 삭제·폐기 증거 보존·새 프로세스 재허용 거부를 확인했다.
  최종 비동기 파일 정리 뒤 만료/폐기를 다시 검사하고 lock 해제 뒤 추가 await 없이 반환한다.
- [Linux CI 34263512267](https://github.com/sihoon-0077/MCPShield/actions/runs/34263512267)
  (`5e8c197`)는 위 대시보드 계약 불일치 및 PostgreSQL 동시 open의 `40P01` 교착상태로 실패했다.
  마이그레이션끼리의 advisory lock은 있었지만 매 open의 트리거 DDL 재실행이 이미 실행 중인
  업무 transaction과 경합했다. `3285714`에서 적용 이력·checksum 및 병렬 실제 PG 회귀를 보완했다.
  새 builder·prepared Docker 전체 회귀·최신 서명 image 단계는 이 실행에서 도달하지 못했다.
- `6e0ab7b`를 [Linux CI 34264417839](https://github.com/sihoon-0077/MCPShield/actions/runs/34264417839)로
  다시 실행 중이다. Node 22/24·실제 PostgreSQL·실제 Docker 및 승인 게이트 후 10회 데모 반복을 요청했다.
  시작/진행 중 상태는 통과 증거가 아니며 결과 확인 전에는 해당 항목을 완료로 표시하지 않는다.
  secret scan은 전체 파일을 검사하고 정확한 비밀키 유출 방지 assertion만 non-secret 예외로 추가했다.
- clean `de4fc9f`의 실제 로컬 EVM·SQLite·HTTP 측정(40회/동시4/identity4):
  hot p95 83.500ms, uniform p95 60.727ms, signed REVOKED 40/40 BLOCK·캐시 재사용0회,
  해당 BLOCK p95 46.899ms, 다음 admission의 차단 확인 49.126ms.
  시작/종료 source hash는 `0585e0af2b31e72e6daee7f645f2c83a8432d346dff1e26e01094ac97cb3cc1f`로 동일하다.
  작은 Windows/Ganache 실험이며 운영 SLO·1만 key·실제 네트워크 장애 측정이 아니다.

명시적으로 남은 구현은 범용 OCI 실행/관측, legacy 정책의 검증자 독립 재실행,
조직 indexer·직접 RPC fallback 및 서명된 break-glass 감사, 문서의 전체 부하·평가 행렬이다.
실제 AI·Base Sepolia·비공개 S3/KMS·독립 기관·운영 Linux 호스트와 최신 전체 버전 공개 배포는
설정 및 실측이 필요한 별도 미완료 항목이다. 기존 Railway 공개 데모는 보존했다.

## 완료의 의미

코드 존재, 자동 테스트 통과, 실제 배포 동작은 서로 다른 증거다.
기능은 실제 성공·실패 경로와 담당자 외 리뷰를 확인한 후에만 완료로 기록한다.
테스트넷 키, 유료 API, 독립 검증기관, 운영 인프라가 필요한 항목은 실제 연결 전까지
검증 대기로 남긴다. 같은 fixture를 반복한 수치를 일반 탐지율로 표현하지 않는다.

`ponytail` 적용: 기존 모듈과 Node 표준 라이브러리를 우선 재사용한다.
하지만 이번에 명시적으로 요청된 기능·보안 경계·검증은 단순화를 이유로 생략하지 않는다.
자체 archive/semver/PostgreSQL 프로토콜을 만들지 않고 유지보수되는 구현을 사용한다.

## 병렬 작업과 통합 순서

| 담당 | 작업 공간 / 브랜치 | 우선 작업 |
|---|---|---|
| Main | MCPShield-master-main / master/main | 요구사항·인터페이스, 운영·CI, 병합·교차 리뷰·E2E |
| Security·AI | MCPShield-master-security-ai / master/security-ai | 안전한 수집, 정적·AI·격리 분석, Merkle 증거, 평가 |
| Blockchain·Backend | MCPShield-master-blockchain-backend / master/backend-prepared | 내구성 작업·권한·정책 API, Trust Plane V2, 재처리 |
| Frontend·Gateway | MCPShield-master-frontend-gateway / master/frontend-preparation | 서명 캐시·폐기 전파·정책 집행, 운영 UI |

1. 기존 시연 회귀 확인, 공통 계약 승인, 요구사항 동결.
2. 수집·분석 → 영속 저장·정책·검증 → Gateway·운영 UI 연결.
3. 격리·장애·테넌트 분리·tampering 교차 리뷰 및 Linux 통합.
4. 배포 전 비밀정보 검사, 공개 데모 회귀, 배포 기능별 실동작 확인.
5. 요구사항별 결과와 미검증 경계·개선 우선순위 보고.

## 요구사항 추적

아래는 Main 통합 결과와 아직 필요한 검증이다. `구현`과 `운영 완료`는 다르다.
새 코드가 들어간 뒤 이전 커밋의 CI 성공을 그대로 최신 코드의 성공으로 간주하지 않는다.

| ID | 내용 | 담당 | 현재 Main 구현 / 남은 증거 |
|---|---|---|---|
| FR-001–003 | npm/tarball/OCI 수집, 불변 버전, 출처 | Security / Backend | bounded npm/tar·OCI blob 검증·공개 OCI API 입력. supplied-lock npm closure의 digest-pinned offline 설치 구현, Linux 실제 검증 진행. 실행 관측·Gateway 연결과 lock 없는 npm·범용 OCI 실행은 진행 중 |
| FR-004–006 | artifact·manifest·전체 tool surface hash | Security / Gateway | JCS·Unicode/변조 벡터, Docker 내부 전체 MCP pagination 수집, Gateway private 전체 pagination·중복/cursor/drift 거부·실제 2페이지 stdio 통과 |
| FR-007–008 | 스캔 중복 방지·자동 기준선 | Backend / Security | 다른 key 유효 결과 재사용·이전 VERIFIED 자동 기준선·명시적 비교 버전·원자적 tenant quota 구현. 실제 PostgreSQL·Linux 회귀 `5cabc48` 통과 |
| FR-101–104 | 메타데이터·코드·변경점·SBOM | Security | schema/annotation/dependency/install diff, SBOM·metadata 규칙 구현. 외부 MCPTox 485 poisoned-tool records의 static review recall 실측 126/485=25.98%; 목표 미달 |
| FR-105–106 | 안전한 AI JSON·근거·권장 테스트 | Security | 공식 Responses·strict JSON·host 계산 citation·독립 Critic·provenance 구현. 계약 서버 테스트 통과; 실제 provider 호출 미실행 |
| FR-107–109 | 일회성 격리·리소스 제한·egress 정책 | Security / Main | 실제 Linux Docker readonly/capability/cgroup/외부연결 차단·통제 proxy 통과. kernel escape 방어의 완전한 증명은 아님 |
| FR-110–112 | canary 유형·생성 테스트·통합 trace | Security / Main | 8종 합성 canary·유출 hash 연결·MCP trace·AI 생성 probe 및 동일 정상 과제 paired-agent 계약 실험 Linux Docker 6개 통과. 실제 외부 모델 호출은 미실행 |
| FR-113 | AI 단독 영구 폐기 금지 | Security / Backend | 결정론적 근거 없는 FAIL 금지, incomplete/Critic 미완료 ABSTAIN 정책 테스트 통과 |
| FR-201–204 | versioned policy·reportRoot·validity·EIP-712 | Backend | V2 typed-data binding·다른 chain/contract/nonce/set replay 거부, validator 로컬 domain/types 재구성·독립 RPC identity·정확한 calldata 확인 로컬 EVM 통과 |
| FR-205–206 | 중복 투표 방지·2-of-3 | Backend | 실제 EVM 정족수·중복 거부·반대 투표 순서 독립성 통과. 검증자는 독립 기관이 아닌 개발용 지갑 |
| FR-207–212 | 격리 TTL·terminal 폐기·이벤트·거버넌스 | Backend | 서명된 1인 격리·최대24h·fresh approval TTL·terminal 폐기·1일 validator 변경 지연·nonproxy 구현. 테스트넷 배포 미실행 |
| FR-301–304 | MCP wrapper·실행 전 차단·surface pinning | Gateway / Security | 실제 SDK stdio·두 Gateway pre-spawn 거부. 초기화 전 호출/비정상 envelope/resources/prompts/서버 sampling·elicitation 우회 차단 로컬 통과 |
| FR-305–306 | 정책·유효기간·freshness·signed cache | Gateway / Backend | Ed25519 서명·tenant/chain/policy/operation binding, strict/balanced 읽기 전용 장애 캐시·폐기 후 재허용 금지 테스트 통과 |
| FR-307–310 | 실행 중 폐기 전파·안내·framing·호환성 | Gateway | 후속 호출 재검사·목록 변경 중단, legacy/stateless matrix·stderr 원문 제거·EOF 강제 종료 통과. 다음 호출 없는 지속 실행의 즉시 중단 SLA는 별도 경계 |
| FR-401 | scan→validator→chain→admission trace | Main / 모든 파트 | 실제 로컬 EVM+공식 OTLP HTTP에서 scan→validator→chain→indexer→evidence-bound admission 27개 연결 span 확인. 전체88 spans·3회export·53,741 bytes. 루프백 계약 수집 서버이며 운영 collector/외부기관 분산배포는 아님 |
| FR-402–403 | 운영 검색·증거 권한·감사 기록 | Frontend / Backend | `/console`→API→worker→암호화 evidence→appeal·reader403, V2 제출/확정·현 상태/역사 상태·admission 구분 UI7개 회귀 통과. receipt UI 추가 통합 진행 |
| FR-404–405 | retry·DLQ·scan/chain idempotency | Backend | 영속 SQL queue·lease·DLQ·atomic 감사 기록·signed raw-tx outbox·재전송/재편성·registry domain 분리 통과. DLQ retry도 tenant queue 한도 검사 |
| FR-406 | 이의제기·재검증·history | Frontend / Backend | 이의제기 생성·release history 연결, retry UI/API 구현. 정책 변경 후 재검증/오탐 해소 전체 flow 추가 검증 필요 |
| FR-407 | 선택적 고위험 action receipt root | Gateway / Backend | opt-in SQLite hash chain·127개 Merkle batch·별도 immutable EIP-712 anchor·tenant API·암호화 evidence·durable outbox·writer CLI 구현. 실제 EVM에서 N-confirmation·reorg ORPHANED·같은 raw tx 복구 통과. 외부 앵커 배포는 미실행 |

## 기능표 밖의 마스터 문서 항목

| 문서 영역 | 구현 / 검증 산출물 |
|---|---|
| 2.5·2.6·부록 A | 불변식 및 장애·archive·redaction 수용 테스트 |
| 3·9·10 | admission/scan 부하 측정, queue 제한, dedup, 비용·보존 설정; 규모는 측정치와 목표 구분 |
| 11 | timeout·retry·DLQ, reorg·RPC·worker 장애 테스트, backup/restore·복구 runbook |
| 12 | OTel trace, metrics·alerts 설정, 운영 상태·감사 조회 |
| 14 | schema·migration·CI·보안 검사·Linux one-command stack |
| 15–18·부록 B | 기존 데모·피치 보존, 제출 증빙과 기능 주장 정합성 점검 |
| 19–21 | observe/warn/enforce, 한계·도입 모델·오탐 대응 문서 |

## 외부 환경 경계

- 개발 PC에서 Docker 실행 파일 및 사용 가능한 WSL 배포판을 확인하지 못했다.
  Linux CI에서 컨테이너·PostgreSQL 실제 테스트를 실행하고 있다.
- 공개 Railway 데모의 replay/local ledger는 실제 테스트넷 검증 결과가 아니다.
- 실제 LLM·테스트넷 배포·독립 validator 운영은 설정 및 실행 증거 전까지 완료로 표시하지 않는다.
- 멀티리전 목표 QPS·가용성 SLO, 외부 데이터셋의 일반화 성능은 구성 파일만으로 달성할 수 없다.

## 현재 검증 증거

- [CI run 34250549056](https://github.com/sihoon-0077/MCPShield/actions/runs/34250549056),
  커밋 `5cabc4896a77ff56216b035805c44faa95c4a105`: Node 22·24·PostgreSQL·Linux 실제 Docker/Compose 통과.
  실제 release image `sha256:bd732dd52cd058dac91533a470e69508af4c39a5c66e97ff26ed7af428d3ea7e`에서
  readonly/nonroot 웹·legacy/modern HTTP MCP·합성 메일·종료 테스트 성공.
  OS+실제 앱 의존성 237개 coverage·HIGH/CRITICAL 0·CycloneDX 검증 통과.
  archive SHA-256 `7e13c1d4cc79021b3c5f495d31ba94de2b2303da3c599ea656fd0ffe5d67a16d`의
  [provenance](https://github.com/sihoon-0077/MCPShield/attestations/46020998)와
  [SBOM](https://github.com/sihoon-0077/MCPShield/attestations/46021010) 서명·저장소 신원 검증 성공.
  이는 서명된 CI 산출물이며 새 Railway 운영 배포·라이선스 승인 또는 무취약성 보증은 아니다.
- 앞선 `65a0858` run `34247767028`의 앱 통합 검증은 성공했으나 image gate에서
  OpenSSL·기본 이미지의 사용하지 않는 전역 npm dependency HIGH/CRITICAL 13건이 발견됐다.
  실행 이미지에서 필요 없는 npm·Yarn 제거, OpenSSL upgrade, 불변 입력 read-only scan으로 수정해
  위 `5cabc48`에서 실제 재검증했다. 검사 실패를 ignore하거나 심각도를 내려서 통과시키지 않았다.
- `7890fa9` Main 전체 `npm test`와 `npm run build` 성공. 이후 추가된 prepared closure·Grafana·
  fullcycle trace는 `66dd503` Linux CI에서 별도 검증 중이다. Windows에서는 Docker 회귀를 명시 skip한다.
- [CI run 34246201330](https://github.com/sihoon-0077/MCPShield/actions/runs/34246201330),
  커밋 `af361b0`: Node 22·24·PostgreSQL·실제 Docker scan→V2→Gateway·Compose 검증 성공.
  별도 signed-image 단계는 Trivy DB 압축 해제 중 `/tmp` 128MiB 한도로 실패했다.
  `65a0858`에서 비공개 CI 임시 작업 공간으로 수정했다. 후속 실제 서명 성공 증거는 위 `5cabc48`이다.
- `65a0858` Main 로컬 `npm test`·`npm run build` 모두 성공. Gateway 52/52,
  Security 55 통과·6 Docker 명시 skip, dashboard 4/4. 실제 PostgreSQL/Docker는 CI 증거를 별도로 사용한다.
- `scripts/ops/evaluate-admission.ts`: 실제 로컬 EVM·SQLite WAL·HTTP·서명 검사 및 gas 측정.
  별도 clean checkpoint `f6b701b`의 40회/동시4/identity4 측정에서 strict hot p95 83.628ms,
  uniform 66.341ms, 실제 signed REVOKED BLOCK 40회·p95 52.469ms. 캐시 허용40회/기존 폐기캐시 재사용0회.
  예상 API/RPC 장애는 각각 FAIL_CLOSED_ERROR로 구분하며 오류를 실제 REVOKED BLOCK으로 세지 않는다.
  source/HEAD/dirty snapshot이 시작·종료에 다르면 NOT_COMPARABLE로 실패한다. 작은 로컬 Windows/Ganache
  실험이며 실제 네트워크 timeout·1만 key 부하·운영 QPS/SLO·테스트넷 성능 또는 일반 탐지율이 아니다.
- `benchmarks/results/mcptox-static-2026-09-09.json`: 고정 upstream 파일 hash 기반 원문 미포함 집계.
  static review recall 25.98%, FPR·agent ASR 미측정. upstream에 명시적 라이선스가 없어 원문을 재배포하지 않는다.
- `node --import tsx scripts/ops/evaluate-reference-metadata.ts`: 공식 reference 서버의 고정 커밋
  `d73f99ef...` 3개 TS 파일을 실행 없이 AST로 읽고 이름·설명 literal만 검사했다. 24개 중 review 0개.
  원문은 저장하지 않는다. 이 표본은 독립 benign label·전체 schema/runtime 평가가 아니므로 FPR=0 또는 안전 인증으로 인용하지 않는다.
- [CI run 34243713559](https://github.com/sihoon-0077/MCPShield/actions/runs/34243713559),
  커밋 `439fba0`: Node 22·24 test/build, 실제 Docker 보안 4/4,
  collector·Prometheus 규칙 검사, 전체 Compose의 LIVE/EVM·두 Gateway BLOCK,
  실제 PostgreSQL 및 별도 DB 복원 모두 성공. production npm audit 0건.
- `414b9e8` 이후 Main 로컬: `tests/api/v2-fullcycle.test.ts`에서 실제 EVM 등록·정책·정족수·격리·폐기,
  공식 SDK initialize/listTools/callTool, 두 Gateway pre-spawn 거부, crash 재전송 및 reorg 복구 통과.
  이 테스트의 report-fixture 실행과 실제 Docker 스캐너 실행은 별개 테스트다.
- `18647fb` 이후 Main `test:dashboard` 4/4: 실제 backend worker까지 연결한 콘솔 기능,
  HttpOnly/Origin·CSRF, reader 권한 거부, streaming body 상한/timeout.
- `c39a68f`: 공식 AWS SDK를 사용한 S3 계약 테스트 2/2; signed HTTP·SSE·조건부 생성·bounded body,
  tenant AES-GCM·기존 객체 변조 시 재시도 거부 검증. 실제 cloud S3 연결은 미실행.
- `28e8773`: supplied-lock npm closure를 입력 snapshot·registry SRI·전체 dependency path/type/mode/content hash로
  고정하는 Docker 구현. 단계는 CLOSURE_PREPARED/INCONCLUSIVE이며 실제 tools/list와 Gateway로 연결하기 전에는
  READY/PASS가 아니다. `ba01af2`에서 builder 자체의 실제 이미지 취약점 검사와 Linux 준비/실행 회귀 게이트 추가.
- `cd74bc9`: 비공개 Grafana 13.2.1 파일 프로비저닝·6개 실제 metric query·No data 경계·익명 차단 구성.
  직접 만든 비밀번호는 출력/재설정하지 않는다. 실제 collector→Prometheus→Grafana CI 검증은 진행 중.

## 아직 완료로 표시할 수 없는 영역

1. 최신 prepared npm closure·Grafana·전체 exporter trace의 Linux/PostgreSQL 통합 회귀.
2. npm prepared image의 실제 관측·최종 release identity·validator·Gateway까지의 통합,
   lock 없는 package의 격리 lock 생성, OCI runtime 실행.
3. 고위험 receipt UI와 오래된 앵커 reorg 복구, 모든 운영 UI 세부 항목.
4. 실제 외부 LLM·Base Sepolia·비공개 S3/KMS/보존 정책·독립 validator 운영 검증.
5. hot/uniform·cache/RPC 장애 smoke 측정의 큰 표본 반복/운영 환경 검증, 다중 크기 scan 처리량·10회 전체 데모,
   외부 라이선스 확인 데이터셋·독립 라벨·전체 ablation/실제 모델 agent ASR.
6. 공개 새 버전 배포, 최종 HEAD signed release 산출물·보안/라이선스 정책·배포/복원 증빙 점검.

이 목록은 작업 범위를 줄이는 제외 목록이 아니라 남은 작업/외부 검증 목록이다.
