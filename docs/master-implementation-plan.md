# MCPShield 마스터 문서 구현 현황

기준일: 2026-09-08. 상태: **구현 진행 중 — 전체 완료 아님**.

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

아래 상태는 시작 시점의 보수적 기준선이다. 작업 브랜치의 구현만으로 완료로 바꾸지 않는다.

| ID | 내용 | 담당 | 시작 시점 / 필요한 추가 검증 |
|---|---|---|---|
| FR-001–003 | npm/tarball/OCI 수집, 불변 버전, 출처 | Security / Backend | 고정 로컬 fixture만 지원; resolver 필요 |
| FR-004–006 | artifact·manifest·전체 tool surface hash | Security / Gateway | 기존 digest 있음; manifest·pagination·canonical vectors 보강 |
| FR-007–008 | 스캔 중복 방지·자동 기준선 | Backend / Security | 작업·정책 기준 dedup 및 version graph 필요 |
| FR-101–104 | 메타데이터·코드·변경점·SBOM | Security | 기초 규칙 있음; 전체 필드·dependency diff 보강 |
| FR-105–106 | 안전한 AI JSON·근거·권장 테스트 | Security | 로컬 구조화 fallback 있음; 실제 provider·schema·이중 평가 검증 필요 |
| FR-107–109 | 일회성 격리·리소스 제한·egress 정책 | Security / Main | Docker 코드 있음; 실제 Linux 격리 실행 증거 필요 |
| FR-110–112 | canary 유형·생성 테스트·통합 trace | Security / Main | 단일 canary 있음; 유형·시나리오·trace 확대 필요 |
| FR-113 | AI 단독 영구 폐기 금지 | Security / Backend | 기존 판정 경계 회귀 및 새 정책 연결 필요 |
| FR-201–204 | versioned policy·reportRoot·validity·EIP-712 | Backend | 기존 서명 있음; V2 전체 필드 결합 필요 |
| FR-205–206 | 중복 투표 방지·2-of-3 | Backend | 기존 로컬 EVM 테스트 있음; V2 재검증 필요 |
| FR-207–212 | 격리 TTL·terminal 폐기·이벤트·거버넌스 | Backend | 기존 폐기 있음; TTL·set 교체·고정 bytecode 배포 증거 필요 |
| FR-301–304 | MCP wrapper·실행 전 차단·surface pinning | Gateway / Security | 기존 실제 MCP 테스트 있음; 범용 artifact 격리 연결 필요 |
| FR-305–306 | 정책·유효기간·freshness·signed cache | Gateway / Backend | 새 admission 및 장애 matrix 필요 |
| FR-307–310 | 실행 중 폐기 전파·안내·framing·호환성 | Gateway | 기존 stdio/HTTP 있음; 두 client·protocol matrix 확대 |
| FR-401 | scan→validator→chain→admission trace | Main / 모든 파트 | 공통 OTel 계측 및 실제 trace 검증 필요 |
| FR-402–403 | 운영 검색·증거 권한·감사 기록 | Frontend / Backend | 데모 UI 있음; 운영 API와 tenant 분리 필요 |
| FR-404–405 | retry·DLQ·scan/chain idempotency | Backend | 기존 chain operation lease 있음; durable scan worker 필요 |
| FR-406 | 이의제기·재검증·history | Frontend / Backend | 신규 구현 필요 |
| FR-407 | 선택적 고위험 action receipt root | Gateway / Backend | 기본 집행 검증 후 선택 기능 구현·독립 표시 |

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
  Linux CI에서 컨테이너·PostgreSQL 실제 테스트를 실행할 계획이다.
- 공개 Railway 데모의 replay/local ledger는 실제 테스트넷 검증 결과가 아니다.
- 실제 LLM·테스트넷 배포·독립 validator 운영은 설정 및 실행 증거 전까지 완료로 표시하지 않는다.
- 멀티리전 목표 QPS·가용성 SLO, 외부 데이터셋의 일반화 성능은 구성 파일만으로 달성할 수 없다.
