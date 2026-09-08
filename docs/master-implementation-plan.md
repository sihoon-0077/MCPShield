# MCPShield 마스터 문서 구현 현황

기준일: 2026-09-09 KST. 상태: **구현 진행 중 — 전체 완료 아님**.

기준 문서: 사용자가 제공한 `MCPShield_전체_시스템디자인_해커톤_마스터문서.md`.
원본 SHA-256: `702268984174af450276b5292a4afccd6a4d5dce79738fe3abde41c4d30d4ea2`.
시작 커밋: `6aa370285154f683989f2bf9b219bd2c052e6cee` (`mcp/main`).
기존 코드·공개 데모를 보존하고 `master/main`에서 통합한다.

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
| Blockchain·Backend | MCPShield-master-blockchain-backend / master/blockchain-backend | 내구성 작업·권한·정책 API, Trust Plane V2, 재처리 |
| Frontend·Gateway | MCPShield-master-frontend-gateway / master/frontend-gateway | 서명 캐시·폐기 전파·정책 집행, 운영 UI |

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
| FR-001–003 | npm/tarball/OCI 수집, 불변 버전, 출처 | Security / Backend | bounded npm/tar·OCI blob 검증과 공개 OCI API 입력 구현. OCI 실행·범용 dependency 설치 미지원 |
| FR-004–006 | artifact·manifest·전체 tool surface hash | Security / Gateway | JCS·Unicode/변조 벡터, Docker 내부 전체 MCP pagination 수집 통과. Gateway pagination 교차 리뷰 수정 진행 |
| FR-007–008 | 스캔 중복 방지·자동 기준선 | Backend / Security | 동일 idempotency-key 중복 방지 구현. 다른 key의 유효 결과 재사용·이전 VERIFIED 자동 기준선 구현 중 |
| FR-101–104 | 메타데이터·코드·변경점·SBOM | Security | schema/annotation/dependency/install diff, SBOM, 숨은 Unicode·명시적 유도 문구 규칙 구현. 암시적 공격 일반 탐지율은 검증되지 않음 |
| FR-105–106 | 안전한 AI JSON·근거·권장 테스트 | Security | 공식 Responses·strict JSON·host 계산 citation·독립 Critic·provenance 구현. 계약 서버 테스트 통과; 실제 provider 호출 미실행 |
| FR-107–109 | 일회성 격리·리소스 제한·egress 정책 | Security / Main | 실제 Linux Docker readonly/capability/cgroup/외부연결 차단·통제 proxy 통과. kernel escape 방어의 완전한 증명은 아님 |
| FR-110–112 | canary 유형·생성 테스트·통합 trace | Security / Main | 8종 합성 canary·실제 유출 항목 hash 연결·MCP request/response trace 구현. AI 생성 probe 추가분의 실제 Linux 회귀 대기 |
| FR-113 | AI 단독 영구 폐기 금지 | Security / Backend | 결정론적 근거 없는 FAIL 금지, incomplete/Critic 미완료 ABSTAIN 정책 테스트 통과 |
| FR-201–204 | versioned policy·reportRoot·validity·EIP-712 | Backend | V2 전체 typed-data binding 및 다른 chain/contract/nonce/set replay 거부 로컬 EVM 통과 |
| FR-205–206 | 중복 투표 방지·2-of-3 | Backend | 실제 EVM 정족수·중복 거부·반대 투표 순서 독립성 통과. 검증자는 독립 기관이 아닌 개발용 지갑 |
| FR-207–212 | 격리 TTL·terminal 폐기·이벤트·거버넌스 | Backend | 서명된 1인 격리·최대24h·fresh approval TTL·terminal 폐기·1일 validator 변경 지연·nonproxy 구현. 테스트넷 배포 미실행 |
| FR-301–304 | MCP wrapper·실행 전 차단·surface pinning | Gateway / Security | 실제 SDK stdio 호출과 2 Gateway pre-spawn 폐기 차단 통과. 초기화 전 호출/잘못된 JSON-RPC 우회 교차 리뷰 수정 중 |
| FR-305–306 | 정책·유효기간·freshness·signed cache | Gateway / Backend | Ed25519 서명·tenant/chain/policy/operation binding, strict/balanced 읽기 전용 장애 캐시·폐기 후 재허용 금지 테스트 통과 |
| FR-307–310 | 실행 중 폐기 전파·안내·framing·호환성 | Gateway | 후속 호출 재검사·목록 변경 시 중단 구현. 공식 legacy/stateless matrix·stderr/EOF 종료 보강 중 |
| FR-401 | scan→validator→chain→admission trace | Main / 모든 파트 | 공식 OTel trace·metric exporter와 비전송 상태에서도 유효한 trace ID 검증. 전체 실제 분산 경로의 단일 trace 증거는 추가 필요 |
| FR-402–403 | 운영 검색·증거 권한·감사 기록 | Frontend / Backend | 실제 `/console`→API→worker→암호화 evidence→appeal 및 reader403 통과. 새 V2 vote/tx 상세 UI 연결은 추가 필요 |
| FR-404–405 | retry·DLQ·scan/chain idempotency | Backend | 영속 SQL queue·lease·DLQ·atomic 감사 기록·signed raw-tx outbox·재전송/재편성 테스트 통과. registry 변경 domain 분리 수정 중 |
| FR-406 | 이의제기·재검증·history | Frontend / Backend | 이의제기 생성·release history 연결, retry UI/API 구현. 정책 변경 후 재검증/오탐 해소 전체 flow 추가 검증 필요 |
| FR-407 | 선택적 고위험 action receipt root | Gateway / Backend | local append-only hash chain·Merkle 및 실제 앵커 기능 작업 예정. 앵커 완료 주장 없음 |

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
- `ff35626`: 수동 실행 전용 signed-image CI 구성 추가. 실제 image vulnerability/license scan,
  CycloneDX·provenance/SBOM 서명·GitHub 신원 검증을 수행하도록 구성했으나 아직 실행 증거 없음.

## 아직 완료로 표시할 수 없는 영역

1. Gateway 교차 리뷰에서 발견한 초기화·pagination·비정상 frame 우회, outbox registry domain 분리 수정의 통합 회귀.
2. AI 생성 probe와 실제 Docker scan→V2 chain→Gateway 전체 Linux 최신 코드 회귀.
3. 범용 npm dependency의 격리 설치·OCI runtime 실행, 고위험 receipt 앵커, 모든 운영 UI 세부 항목.
4. 실제 외부 LLM·Base Sepolia·비공개 S3/KMS/보존 정책·독립 validator 운영 검증.
5. hot/uniform·cache/RPC 장애 부하 실험, 다중 크기 scan 처리량·gas/전파 시간·10회 전체 데모,
   외부 라이선스 확인 데이터셋·독립 라벨·전체 ablation/agent ASR.
6. 공개 새 버전 배포, signed release 산출물·보안/라이선스 정책·배포/복원 증빙 최종 점검.

이 목록은 작업 범위를 줄이는 제외 목록이 아니라 남은 작업/외부 검증 목록이다.
