# 마스터 원문 재감사 — Backend / Trust / 운영 확장

기준일: 2026-09-19 KST. 코드 기준: `e55c1ab`(Backend `208fa2c` 통합). 이 문서만 작성했으며 기능·설정·배포는 변경하지 않았다.

원문: `C:/Users/박시훈/Downloads/MCPShield_전체_시스템디자인_해커톤_마스터문서.md`.
SHA-256: `702268984174af450276b5292a4afccd6a4d5dce79738fe3abde41c4d30d4ea2`.
**965–1711, 2091–2485, 2825–3428을 줄 단위로 전부 읽었다.** FR 매핑에는 원문의 506–574행도 대조했다.

## 판정 방식

- **완료**: 해당 행의 좁은 기능을 코드와 실행 증거로 확인했다. 실제 기관 운영·서비스 SLA·외부 AI 품질까지 완료라는 뜻이 아니다.
- **부분**: 하위 기능은 있지만 명시한 필드·운영 조건·통합 실행 증거 일부가 없다. 설정/테스트 파일만 있는 경우도 포함한다.
- **미완료**: 해당 동작 구현 또는 실제 운영 검증을 찾지 못했다. 금지한 기능을 억지로 구현하라는 뜻은 아니다.
- FR이 있는 행은 FR 원장에 **매핑하는 세부 증거**이지 새 완료 건수가 아니다. `중복 → Bxx`는 다시 세지 않는다. 대안·예시·확장 계획은 coverage note에 남기고 기능 분모에 임의로 더하거나 빼지 않는다.
- API JSON/SQL/의사코드 예시는 바이트 단위 동일 구현을 요구하지 않되, 예시에만 있는 기능(진행률·callback·우선순위 등)은 별도 미충족으로 표시했다.
- 이 범위의 행 수로 전체 진척률을 계산하지 않는다. 원문의 동등하지 않은 기능·운영 목표와 여러 번 반복된 요구를 합산하면 잘못된 백분율이 된다.

## 실행 증거와 한계

1. Backend 통합 직전 같은 기능 패치 `208fa2c`: `node --import tsx --test tests/api/*.test.ts` **85 PASS / 11 SKIP**, backend 타입 검사 성공. 직전 실행 전 config 재비교 추가 후 scoped 전용 **7 PASS / 0 SKIP**, 타입 검사 재통과. PG/Docker 조건부 skip은 성공으로 세지 않았다.
2. `e55c1ab`에서 본 감사자가 V2 contract, S3 HTTP 계약, Gateway fallback/break-glass 검사를 재실행했다. 실제 로컬 EVM·HTTP·프로세스이며 외부 체인/클라우드/Safe/HSM 검증이 아니다. 아래 명령은 종료 코드 0이다.

   ```sh
   node --import tsx --test tests/contracts/release-registry-v2.test.ts tests/integration/object-storage.test.ts apps/gateway/test/admission-fallback.test.mjs apps/gateway/test/break-glass.test.mjs
   ```

3. 저장된 Main 실행 기록: [`0351567` / CI 35425746994](https://github.com/sihoon-0077/MCPShield/actions/runs/35425746994), PostgreSQL job `105851290825`: **40 PASS / 1 native SKIP**, 별도 빈 DB backup/restore 성공, Node 24 성공. Node 22의 기존 OCI fullcycle 및 npm prepared fullcycle 성공 단계 기록이 있다. 이는 **이전 SHA의 일부 증거**이며 e55c1ab scoped-v2 전체 Linux 통과와 같지 않다. 전체 run 최종 상태는 Main 종합 원장에서 갱신한다.
4. 새 Node scoped-v2의 실제 Docker 게이트는 `tests/api/prepared-fullcycle.test.ts`의 `scoped Node v2 source` 테스트다. `MCPSHIELD_DOCKER_TESTS=1`, `MCPSHIELD_SCOPED_DOCKER_TESTS=1`, 정확한 로컬 builder CID가 필요하다. 이 감사 환경에서는 실행하지 않았다.
5. Security는 sourceBudget/로컬 catalogue/원본 재획득 권한을 교차 리뷰했고, Frontend는 `chainUnavailable` 보존 및 cross-mode scan/appeal 409·slot 미소비를 실제 in-memory API로 재검증했다. 이 리뷰를 실제 독립기관 보안 인증으로 표현하지 않는다.
6. Main 전달 최신 상태(이 감사 코드 스냅샷과 분리): `e55c1ab` 전체 `npm test` 종료 0 및 backend+Turbopack build 성공. `1686547` 안내 추가 뒤 focused 14 PASS/typecheck 성공. 원격 `7bac78a689b478e2aa6f4e2714a425d5c17a263b`의 [dispatch 35427980359](https://github.com/sihoon-0077/MCPShield/actions/runs/35427980359)는 **진행 중**이며 Node 24/PostgreSQL job 성공이다. **Node 22 step 14 scoped Node scanner native는 실패**, 이후 step 19 진행 중으로 전달받았다. 원인 로그는 이 감사자가 확인하지 않았으므로 원인을 추정하지 않는다. 같은 SHA push run `35427980544`은 dispatch로 대체 취소. 최신 scoped-v2 native/전체 CI를 완료로 표기하지 않으며 최종 상태는 Main이 보정한다. 실패 수정을 이번 감사에서 수행하지 않았다.

## 증거 색인

아래 `E##`는 표의 축약 참조다. 파일 경로는 저장소 루트 기준이며 함수명/테스트 제목을 함께 적었다.

| 참조 | 코드·시험 근거 |
|---|---|
| E01 | `packages/contracts-sdk/src/v2-identity.mjs`의 `exactReleaseIdentity`; `services/resolver/src/resolver.mjs`의 `resolveArtifact`; `tests/api/v2-trust.test.ts`, `tests/security/master-scanner.test.mjs` |
| E02 | `apps/api/src/control-plane.ts`의 `/v1` routes·`publicRelease/publicScan`, `control-policy.ts`, `control-config.ts`; `tests/api/control-plane.test.ts`, `scoped-preparations.test.ts` |
| E03 | `apps/api/src/control-store.ts`의 `enqueueConstrained/claim/finish/fail`, `preparation-store.ts`; `tests/api/control-plane.test.ts`, `preparations.test.ts`, `appeals.test.ts`; PG CI는 위 3번 |
| E04 | `database/migrations/002_control_plane.sql`, `003_scan_audit.*.sql`, `004_chain_outbox.sql`, `006_scan_request_keys.sql`, `009_scan_trace_index.*.sql`, `010_runtime_preparations.sql` |
| E05 | `services/scanner/src/evidence.mjs`의 path-leaf SHA-256 Merkle 생성·proof; `canonical-json.mjs`, `tool-surface.mjs`; `tests/security/master-scanner.test.mjs` |
| E06 | `apps/api/src/control-plane.ts`의 `saveEvidence/loadEvidence` 및 역할별 evidence route; `packages/object-storage/index.mjs`; `tests/api/control-plane.test.ts`, `tests/integration/object-storage.test.ts` |
| E07 | `apps/api/src/event-stream.ts`의 `/events/stream`(resync 알림), `/events` REST; `tests/api/event-stream.test.ts` |
| E08 | `apps/api/src/control-worker.ts`, `control-worker-cli.ts`, `preparation-worker.ts`; `compose.control.yml`; `tests/api/preparations.test.ts`, `prepared-fullcycle.test.ts` |
| E09 | `services/resolver/src/resolver.mjs`, `oci.mjs`, `npm-closure.mjs`, `oci-runtime.mjs`; `tests/security/{master-scanner,oci-resolver,oci-acquisition,npm-closure}.test.mjs` |
| E10 | `services/scanner/src/{scanner,analysis,prepared-scan,prepared-policy,scoped-semantic,scoped-policy}.mjs`; `tests/security/{scoped-semantic,scoped-prepared,prepared-scan}.test.mjs` |
| E11 | `contracts/src/ReleaseRegistryV2.sol`: `ValidatorRegistry`, `PolicyRegistry`, `ReleaseRegistryV2`; `tests/contracts/release-registry-v2.test.ts`(실제 Ganache) |
| E12 | `contracts/scripts/deploy-v2.ts`, `packages/contracts-sdk/src/v2.ts`, `transport.mjs`; `tests/api/v2-trust.test.ts`; 외부 Base Sepolia 배포 영수증은 이 범위에서 확인하지 못함 |
| E13 | `apps/api/src/chain-control.ts`, `chain-outbox.ts`: payload 서명 검증, nonce lease, raw tx 선저장·동일 bytes 재전송; `tests/api/{v2-fullcycle,reconcile}.test.ts` |
| E14 | `apps/indexer/src/v2-indexer.ts`, `packages/contracts-sdk/src/v2-chain-reader.mjs`; `tests/api/v2-fullcycle.test.ts`, `apps/gateway/test/v2-chain-reader.test.mjs` |
| E15 | `apps/gateway/src/{signed-admission,admission-fallback,index}.mjs`; `apps/gateway/test/{admission-fallback,signed-admission,terminal-revocation-race}.test.mjs` |
| E16 | `apps/gateway/src/{break-glass,protocol-guard,prepared,oci-prepared}.mjs`; `apps/gateway/test/{break-glass,protocol-guard,prepared-docker,oci-prepared-docker}.test.mjs` |
| E17 | `apps/validator/src/{v2,prepared-verification,scoped-verification,source-verification}.ts`; `apps/api/src/scoped-config.ts`; `tests/api/{scoped-validator,prepared-validator,source-validator}.test.ts` |
| E18 | `docs/operations-runbook.md`(S3 설정과 미검증 한계·pg_dump/pg_restore·키 사고); `.github/workflows/frontend-gateway-devops.yml`(실행 게이트); 코드/설정 존재 자체는 운영 성공 증거 아님 |
| E19 | `apps/api/src/control-health.ts`, `worker-health.ts`; `tests/api/health.test.ts`, `scripts/ops/check-control-health.ts`; authenticated 관측과 실패 응답은 구현, autoscaler는 아님 |
| E20 | `apps/api/src/receipt-{control,relayer}.ts`, `apps/indexer/src/receipt-indexer.ts`, `contracts/src/ReceiptAnchorRegistry.sol`; `tests/api/receipt-anchors.test.ts` — 선택적 action receipt이며 릴리스 PASS batch와 구분 |
| E21 | `apps/api/src/control-plane.ts`의 appeal routes, `control-store.ts`의 transaction link/fence; `tests/api/appeals.test.ts`, `scoped-preparations.test.ts` |
| E22 | `apps/dashboard/lib/control-client.ts`의 한국어 상태별 안내, `apps/gateway/src/index.mjs` 오류 응답; `apps/dashboard/test/control-client.test.mts` |

## 1. 식별자·API·모델·증거 (965–1421)

| ID / 원문 행 | 원자 요구 | FR 매핑 | 상태 | 증거 | 미충족·판정 범위 |
|---|---|---|---|---|---|
| B01 / 969–983 | namespace+canonical locator SHA-256 Tool ID | FR-003/004 | 부분 | E01 | 실제 `npm:name`을 ethers `id`(Keccak)로 변환. 원문 namespace/newline 식과 다르며 namespace 분리 모델 미구현 |
| B02 / 984–995 | artifact·manifest·surface를 포함한 exact release identity | FR-004/006/208 | 완료 | E01, E11 | V2 기준. semver만 쓰는 기존 데모 `/api`를 같은 보안 경로로 세지 않음 |
| B03 / 997–1003 | 시간 정렬 UUIDv7 scan ID | 직접 FR 없음 | 미완료 | E03 `randomUUID()` | 현재 UUIDv4+createdAt 정렬; v7 아님 |
| B04 / 1005–1011 | canonical policy hash로 판정을 고정 | FR-201 | 완료 | E02 | alias는 표시용; 실제 scan은 exact policyHash 필수 |
| B05 / 1011,1062–1066 | mutable alias를 입력받아 정책 hash로 해석 | FR-201 세부 | 부분 | E02 | alias 저장은 있으나 public scan에 policyAlias/callbackUrl 허용 안 함. callback 별도 B08 |
| B06 / 1015–1039 | exact source resolve와 digest·출처 응답 | FR-001–004 | 부분 | E01/E02/E09 | npm/tarball/OCI 지원 범위는 제한적. registryUrl/baseline 입력·응답 envelope는 예시와 다름; publisher는 검증된 신원이 아님 |
| B07 / 1041–1048 | resolve 오류 400/404/409/413/422/429별 구분 | FR-001 세부 | 부분 | E02 | validation/권한/쿼터 고정 코드는 있으나 모든 resolver 원인→열거 HTTP status 매핑 미구현 |
| B08 / 1050–1083 | 비동기 scan 202·동일 키 중복 제거·조회 링크 | FR-405 | 완료 | E02/E03 | payload는 releaseId+policyHash. callback webhook·scan별 SSE 링크는 미구현/예시 차이 |
| B09 / 1065,1195–1211 | baseline 지정 및 유효 이전 결과 재사용 | FR-007/008 | 부분 | E03 | legacy source는 구현·시험. prepared Node/OCI의 baseline은 명시적 거절; cross-registry digest 공용 재사용은 없음 |
| B10 / 1085–1103 | 단계별 상태·진행률·시작/전체 deadline 조회 | FR-402/404 | 부분 | E02/E03 | QUEUED/RUNNING/COMPLETED/DEAD_LETTER와 SCANNING/DONE 등은 있음. 72% 같은 실제 stage progress·각 stage 결과·전체 deadline 없음 |
| B11 / 1105–1135 | release 식별자·현재 판정·체인 참조 조회 | FR-402 | 완료 | E02/E14 | flatter schema이며 chainUnavailable+이전 block 구분 회귀 통과. UI 표시/검색 전체는 Frontend 감사 참조 |
| B12 / 1137–1155 | 로컬 typed-data 서명만 API 제출, private key 금지 | FR-203/204 | 완료 | E13/E17 | independent signer 구현. 실제 외부 기관은 B47 |
| B13 / 1157–1183 | exact identity·정책·최신 체인 상태에 기반한 admission | FR-302/305/306 | 완료 | E02/E14/E15 | 고위험 여부와 strict/balanced 집행 일부는 Gateway 로컬 권한; API 예시 필드 전부 제공하는 형태는 아님 |
| B14 / 1185–1193 | 실시간 release state 이벤트 배포 | FR-210/307 | 부분 | E07/E15 | `/events`는 JSON, `/events/stream`은 bounded resync SSE. lossless state-event/cursor·Gateway 해당 SSE 구독은 아님 |
| B15 / 1195–1209 | static/semantic/sandbox 완료·판정·attest 내부 이벤트별 dedup envelope | FR-401/404/405 | 부분 | E03/E07/E08/E13 | scan/chain/audit 이벤트 존재. 원문 단계별 독립 consumer·model/scenario dedup 키·버전 envelope 없음 |
| B16 / 1213–1226 | tool의 namespace·locator·publisher 관계와 uniqueness | FR-003 | 부분 | E04 `cp_records` | 별도 tools 테이블/FK·검증된 publisher 없음; JSON metadata와 tenant ID로 대체 |
| B17 / 1228–1237 | artifact bytes·algorithm·source·object key·retention 모델 | FR-003/004 | 부분 | E01/E04 | bytes/digests/출처는 metadata; artifact 전용 불변 DB 제약·retention_until 없음 |
| B18 / 1239–1249 | release identity uniqueness·baseline 관계 | FR-004/008 | 부분 | E01/E03/E04 | exact identity PK와 scan baseline 존재; SQL FK/전체 버전 그래프·release baseline FK 없음 |
| B19 / 1251–1265 | scan 내구성·lease·attempt·멱등키 | FR-404/405 | 완료 | E03/E04 | tenant scope UNIQUE, 원자 claim/finish/fail 검증. priority 필드는 B104 |
| B20 / 1269–1282 | finding fingerprint 중복 제거·severity 조회 모델 | FR-104/112 | 부분 | E04/E05/E10 | findings는 보고서 JSON에 저장; 전용 findings unique/index·confidence 컬럼 없음 |
| B21 / 1284–1294 | report root·policy·validity·암호화 object 참조 | FR-201/202/403 | 완료 | E02/E06 | 별도 reports 테이블 대신 결과 JSON; redacted report와 raw를 두 객체로 나누는 모델은 아님 |
| B22 / 1296–1308 | validator signature/nonce/expiry 저장·중복 제약 | FR-203–205 | 완료 | E11/E13 | chain action payload+typed digest/contract round로 중복 방지; 물리 schema는 예시와 다름 |
| B23 / 1312–1324 | chainId/tx/logIndex unique, block hash, orphan 처리 | FR-210 | 완료 | E04/E14 | orphan 원본 행은 삭제하고 orphan 감사 event를 별도 기록; canonical boolean 모델과 다름 |
| B24 / 1326–1338 | client/tenant별 admission 결정 기록·시간 partition | FR-401/402 | 부분 | E04/E15 | trace/log·선택 receipt 존재; 문서의 partitioned admission_decisions 원장 및 전 client 영향 검색 없음 |
| B25 / 1341–1348 | 명시한 6종 query index | FR-007/402/404 | 부분 | E04 | queue/release/event/trace index 있음; findings·attestation별 SQL quorum·partitioned admission index 없음 |
| B26 / 1350–1352 | DB projection을 허용 권위로 쓰지 않고 stale이면 RPC/deny | FR-302/305/306 | 완료 | E14/E15 | bound chain storage 읽기·block hash·freshness 검증, 이전 상태는 chainUnavailable 표시 |
| B27 / 1354–1380 | 파일별 검증 가능한 Merkle bundle과 선택 proof | FR-202/403 | 완료 | E05/E06 | finding 단위 leaf가 아닌 path leaf; 정확한 알고리즘 차이는 B57 |
| B28 / 1380 | raw evidence 비공개 암호화·역할 접근·접근 이력 | FR-403 | 완료 | E06 | 로컬/S3 계약 수준. 실제 bucket ACL/보존 운영은 B100 |
| B29 / 1386–1388 | JCS 호환 정렬·UTF-8·원본 Unicode 보존 | FR-005 | 완료 | E05 `canonical-json.mjs` | lone surrogate/nonfinite 거부. 별도 semantic NFC 계층은 B30 |
| B30 / 1388–1390 | semantic NFC representation·volatile icon 별도 hash layer·origin/name 정렬 | FR-005/006 세부 | 부분 | E05/E10 | raw 문자열 보존·name+canonical 정렬은 있음. 세 가지 별도 계층/멀티 origin 정렬 설계 없음 |
| B31 / 1391 | description/schema/annotations를 security hash에 포함 | FR-006/102 | 완료 | E05/E10 | 의미 필드 변경은 다른 hash |
| B32 / 1392–1393 | 전체 페이지 완료 전 승인 금지·외부 schema ref 제한 | FR-006/304 | 완료 | E10/E16 | prepared discovery/Gateway pagination·remote ref 거절; 오류는 불완전/거절 |

## 2. 아키텍처·획득 경계 (1422–1711)

| ID / 원문 행 | 원자 요구 | FR 매핑 | 상태 | 증거 | 미충족·판정 범위 |
|---|---|---|---|---|---|
| B33 / 1424–1432 | API modular backend, 별도 worker/validator/Gateway/chain | FR-107/203/301 | 부분 | E08/E11/E16/E17 | 프로세스·논리 경계 구현. 실제 운영 호스트/계정/기관 독립성 및 worker credential 분리는 B123 |
| B34 / 1434–1507 | 그림의 Registry/PyPI/Sigstore source 연결 | FR-001/003 | 부분 | E09 | npm/OCI 실제 adapter는 있음. PyPI, 공식 MCP registry 자동 ingest, Sigstore/Rekor 검증 연동 없음 |
| B35 / 1445–1463 | Edge rate limit·API/UI/metadata/저장소 연결 | FR-402/405 | 부분 | E02/E06/E08 | 앱 rate limit·SQL queue·로컬 암호화/S3 adapter. 관리형 LB/전역 quota·실제 cloud storage 완료 아님 |
| B36 / 1465–1506 | 격리 실행에서 file/process/network/canary 증거 수집 | FR-107–112 | 부분 | E09/E10/E16, 이전 native CI | 제한된 Node 및 OCI 프로필 실행은 있음. 모든 플랫폼/언어/샌드박스 탈출 방어 증명 아님; scoped-v2 최신 native 미검증 |
| B37 / 1509–1533 | 무거운 scan과 runtime admission 분리 | FR-302/305/404 | 완료 | E02/E03/E08/E15 | admission은 scan을 시작하지 않음. 수십~수백 ms SLO는 기능 완료와 별도 |
| B38 / 1535–1544 | 정책·보고서별 서명자/상태 이력·quorum 공유 | FR-201–210 | 완료 | E11/E13/E14 | 단일 기관 로컬 프로토콜 검증 기준; 기관 분리는 B47 |
| B39 / 1548–1579 | resolve→queue→scan→evidence→validator→chain→projection E2E | FR-001/107/203/206/210 | 부분 | E08/E13/E17, 이전 native CI | 기존 Node/OCI native 성공 단계 있음. scoped-v2 최신 전체 gate·실제 외부 AI·공개 테스트넷 검증 남음; 자동 무인 fan-out scheduler는 없음 |
| B40 / 1581–1622 | exact bytes→cache/API/RPC→격리→surface pinning→proxy | FR-302–306/309 | 완료 | E15/E16, 이전 native CI | 지원 프로필 기준. v2 새 runtime 및 운영 SLO는 별도 검증 |
| B41 / 1624–1642 | 긴급 격리가 두 Gateway의 cache/후속 호출에 전파 | FR-207/307 | 부분 | E11/E13/E15 | quarantine/호출 전 재검사는 있음. indexer→두 Gateway push invalidation E2E는 없음 |
| B42 / 1644–1663 | source별 resolver interface와 재현 가능한 immutable 결과 | FR-001–004 | 부분 | E09 | 함수 dispatch로 구현(명시 interface는 대안). PyPI/fetchPlan 등은 없음 |
| B43 / 1667–1669 | npm exact version·integrity/shasum 검증·독립 SHA-256 | FR-002/004 | 완료 | E09 | 허용 registry 제한. publisher provenance 확인과 별개 |
| B44 / 1670–1672 | package scripts/deps/bin·maintainer 기록 및 설치 위험 분석 | FR-003/103/104 | 부분 | E09/E10 | package/lock/SBOM·install script 제한 있음. repository owner-이름 불일치 판정·신뢰된 publisher 없음 |
| B45 / 1674–1680 | OCI tag→manifest/child pin·layer 검증·runtime config/root 위험 | FR-001–004/103 | 부분 | E09 | 허용 registry, digest/platform/layers/rootUser 구현. privileged expectation/socket 요구의 일반 검출은 미완료; source URI 범위 제한 |
| B46 / 1682–1708 | 실행 discovery는 sandbox에서 하고 auth/capability context별 surface bind | FR-006/107/304/310 | 부분 | E10/E16 | 제한 startup·pagination·초기 행동 증거 있음. scanner surface는 기본 무인증 프로필; 모든 scope별 독립 attestation 미구현 |

## 3. 체인·검증자·상태 (2091–2485)

| ID / 원문 행 | 원자 요구 | FR 매핑 | 상태 | 증거 | 미충족·판정 범위 |
|---|---|---|---|---|---|
| B47 / 2097–2106,2293–2299 | 서로 다른 조직의 검증자/소비자가 공동 상태 운영 | FR-206/211 확장 | 미완료 | E11/E12/E17 | 세 별도 키/process는 있으나 외부기관 참여·조직 독립 운영 증거 없음 |
| B48 / 2100,2287,2376–2381 | conflicting PASS/FAIL equivocation event·탐지 | FR-205/210 세부 | 미완료 | E11 | 동일 round 중복은 거부하지만 ValidatorEquivocation event·상충 서명 제출/탐색 경로 없음 |
| B49 / 2124–2133 | Base Sepolia 실제 배포와 공개 tx/event 재현 | FR-212 | 부분 | E12 | EVM 배포·chainId/domain/manifest 코드와 로컬 EVM은 검증. 현재 V2의 공개 주소·영수증 검증은 없음 |
| B50 / 2135 | 다른 EVM/컨소시엄으로 교체 가능한 ChainAdapter | 직접 FR 없음 | 부분 | E12/E14 | 구성 가능한 RPC/chainId 및 typed reader 있음. 서로 다른 chain adapter 구현·전환 운영 검증 없음 |
| B51 / 2141–2192 | Release/Validator/Policy 3 registry와 활성 set version | FR-201/202/205/206 | 완료 | E11 | 한 Solidity 파일의 3 contract. 동적 정족수는 고정 2/3 구현으로 대체 |
| B52 / 2194–2209 | policy hash/본문 고정·폐기·URI/tier/publication metadata | FR-201 | 부분 | E11/E02 | 불변 documentDigest/publication/deprecated 존재. URI·tier·deprecatedAt 구조는 없음 |
| B53 / 2212,2309 | multisig 또는 지연된 validator 권한 변경 | FR-211 | 부분 | E11/E12 | 1일 rotation timelock/disable version 구현. 외부 admin 주소는 설정 가능하지만 실제 Safe 2-of-3 운영/복구 시험 없음 |
| B54 / 2214–2237 | 정책별 유효 PASS 2/3·FAIL 2/3·전역 terminal revoke | FR-201/205/206/208 | 완료 | E11, E13 | actual local EVM tests. exact release 새 digest 요구. 상태별 유효기간은 storage view와 syncExpiry 사용 |
| B55 / 2236–2239,2306 | 1명 critical code 격리≤24시간, 새 scan quorum으로 해제 | FR-207/113 | 완료 | E11/E13/E17 | enum code allowlist+local evidence gate. contract만으로 evidence의 사실을 증명하지 않음 |
| B56 / 2241–2286 | EIP-712 전체 domain/identity/policy/root/nonce/deadline/set replay 방지 | FR-203–205 | 완료 | E11/E12/E13 | 동일 서명·다른 domain·stale set 거부 실제 EVM 테스트 |
| B57 / 2315–2344 | finding별 keccak leaf·정렬·선택 공개 proof | FR-202/403 세부 | 부분 | E05 | 선택 proof/32byte root는 완료 B27. 구현은 SHA-256(path,file digest) leaf; finding 필드별 독립 proof는 없음 |
| B58 / 2346–2384 | 등록/증명/상태 events와 storage를 최종 권위로 사용 | FR-210/305 | 완료 | E11/E14 | 모든 explicit transition event 존재. 시간 경과는 syncExpiry transaction 전 별도 event가 없으며 view에서 즉시 유효성 판단 |
| B59 / 2418 | (releaseId,policyHash)별 판정 분리 | FR-201/205 | 완료 | E11 | 정책 간 quorum 섞지 않음; revoke/quarantine는 안전한 전역 deny |
| B60 / 2420–2428 | 보수적 허용 confirmation·낮은 confirmation 차단 | FR-305/307 | 완료 | E14/E15 | finalized/head 읽기에서 optimistic deny 우선. 대규모 전파 SLO 아님 |
| B61 / 2422,3338–3340 | optimistic/finalized 상태를 별도 DB·UI 필드로 제공 | FR-402/210 | 부분 | E04/E14 | head/finalized reader와 block checkpoint 있음. UI `PENDING_CONFIRMATION`·이중 projection 필드 완전 구현 아님 |
| B62 / 2428 | block hash 대조·orphan rollback·재동기화 | FR-210/306 | 완료 | E14/E13 | local EVM reorg 경로. 전역 재색인 성능/RTO는 미검증 |
| B63 / 2430–2442 | read-only signed grace, high-risk fail-closed, revoke cache terminal | FR-306 | 완료 | E15 | 위 실제 로컬 EVM/fallback 재시험. 의도적 break-glass는 정상 verdict를 바꾸지 않는 별도 경로 B128 |
| B64 / 2461–2462,2465–2466 | 온체인 원문 최소화·32byte reason·identity 최초1회 | FR-202/209 | 완료 | E11/E13 | 원문/PII 대신 bytes32와 서명 이력; Policy URI 예시는 구현하지 않아 plaintext도 없음 |
| B65 / 2463 | offchain quorum signature bundle 1 tx aggregator | FR-206 확장 | 미완료 | E11/E13 | 서명별 transaction. 선택적 Pilot 최적화이며 현재 승인에 필요한 기능은 아님 |
| B66 / 2471–2472,2475,2481–2482 | CEI·외부 callback/token 없음·Solidity0.8·nonproxy | FR-209/212 | 완료 | E11/E12 | immutable deployment 코드와 로컬 deploy. public bytecode 검증은 B49 |
| B67 / 2473 | OpenZeppelin ECDSA library 사용 | FR-203 세부 | 부분 | E11 `_recover` | low-s/v/길이 검사 자체 구현. 명시 OZ 의존성·독립 crypto audit 없음; 직접 구현을 OZ 사용으로 표기하면 안 됨 |
| B68 / 2476,2480 | 역할 변경 event·setversion·stale 서명 거절 | FR-204/211 | 완료 | E11 | disable/rotation primitive 있음. 조직 키 사고 대응 운영은 B121 |
| B69 / 2477–2479 | terminal/duplicate/policy separation property test | FR-205/208 | 부분 | E11 tests | 결정론적 EVM 회귀는 통과. Foundry invariant fuzz/property runner는 없음 |
| B136 / 2293–2297 | validator A/B/C가 서로 다른 구현 프로필로 판단 | FR-206 확장 | 부분 | E17 | 독립 process/key/새 scanner run은 있음. static 전용·독립 AI 규칙·종합 정책이라는 역할별 다른 구현은 없음 |

## 4. 병목·확장 (2825–3204)

| ID / 원문 행 | 원자 요구 | FR 매핑 | 상태 | 증거 | 미충족·판정 범위 |
|---|---|---|---|---|---|
| B70 / 2841,2866 | digest별 설치 layer 공유 + 실행은 fresh snapshot | FR-007/107 | 부분 | E09/E10 | immutable closure/새 실행 컨테이너 있음. 여러 작업용 digest 설치 cache service 없음 |
| B71 / 2867–2869 | quick/deep scan 프로필과 시간별 시나리오 분리 | FR-108/111 | 미완료 | E02/E10 | tier/probe 예산은 있으나 명시 quick/deep queue·30–60초/5–15분 제품 경로 없음 |
| B72 / 2870 | tenant별 실제 동시 실행 quota | FR-404 확장 | 부분 | E03 | 일일/대기 quota는 있음. tenant별 running slot 상한 별도 없음 |
| B73 / 2871 | 크기·파일 수·압축률 제한 | FR-001/108 | 완료 | E09 tests | 제한 범위 내 npm/OCI이며 임의 크기 지원은 아님 |
| B74 / 2872–2873 | 일회성 worker와 timeout 후 process/network 완전 정리 검증 | FR-107/108 | 부분 | E08/E09/E10, native tests | 후보 container cleanup 있음. worker host 폐기·kernel namespace 누수/탈출 후 격리 검증은 없음 |
| B75 / 2874,3051–3064 | queue age/pending token/lag 기반 autoscale | FR-404 확장 | 미완료 | E03/E19 | 상태/연결 관측과 worker 수 수동 조정은 autoscaler가 아님; KEDA 없음 |
| B76 / 2880–2886 | diff/dependency/sink 중심 bounded AI 입력 | FR-102/105/111 | 부분 | E10 scoped-v2 | Node closure scoped 선택·예산 구현. 신뢰된 baseline diff-first 재사용·추가 context 정책 전체/OCI v2 호출 아직 없음 |
| B77 / 2888–2895,3198 | provider/model/prompt/policy/input digest AI 결과 cache | FR-007 확장 | 미완료 | E10 | 동일 scan 결과 재사용과 AI 역할 cache를 혼동하지 않음. 원문 semantic cache 없음 |
| B78 / 2897–2901 | AI 장애는 review/보류, 기존 VERIFIED 자동 revoke 금지 | FR-113/404 | 완료 | E02/E10/E17 | provider 품질 성공이 아니라 실패 시 안전한 ABSTAIN/REVIEW_REQUIRED 경로 |
| B79 / 2902 | low-risk human override와 감사 | FR-308/401 확장 | 완료 | E16 | 별도 서명·≤60초·정확한 1회 read-only grant. normal verdict 보존; 일반 승인 우회 버튼 아님 |
| B80 / 2910–2913 | validator 동일 canonical 원본·독립 검사·불일치/timeout 비승인 | FR-202/203/206 | 부분 | E05/E06/E17 | 동일 root·독립 evidence 및 ABSTAIN/fixed 오류 거부 있음. quorum deadline scheduler·공개 INCOMPATIBLE_EVIDENCE 상태 모델 완전 구현 아님 |
| B81 / 2911 | validator별 scanner/policy version 기록 | FR-201/401 | 부분 | E10/E17 | policy/collector/observer/receipt commitment 있음. 기관별 scanner release/version 운영 inventory 없음 |
| B82 / 2920 | process+disk signed cache | FR-306 | 완료 | E15 | 재시작 후 revoke journal 포함 실제 OS-process tests |
| B83 / 2921–2922 | cache expiry jitter·동일 lookup single-flight | FR-306 확장 | 미완료 | E15 | pending map은 stale allow fencing이지 요청 합치기 아님. disk lock 거절도 single-flight 결과 공유가 아님 |
| B84 / 2923–2924,3140–3143 | status push invalidation·miss 후 TTL·stateVersion fence | FR-307 | 부분 | E07/E15 | TTL·revocation race epoch/journal은 있음. Redis publish·Gateway SSE·전역 stateVersion 없음 |
| B85 / 2925 | direct RPC 요청 quota | FR-306 | 완료 | E15 | 공통 deadline+고정 process quota 실제 시험. 문서 token-bucket과 알고리즘은 다름 |
| B86 / 2931–2933 | scan은 offchain, 최종서명만 chain, emergency 즉시 경로 | FR-202/206/207 | 부분 | E03/E13 | offchain 결과와 개별 chain action 분리. automatic PASS renewal·emergency priority queue/wallet 없음 |
| B87 / 2935 | webhook 비의존 block polling | FR-210 | 완료 | E14/E08 | indexer poll·hash 대조. 실제 외부 RPC 장애 SLO는 별도 |
| B88 / 2943–2946 | AI-only 영구 차단 금지·별도 deterministic flag | FR-105/106/113 | 완료 | E10/E11/E17 | 코드 정책 검증. 자연어 의미 판단 정확도 완료 아님 |
| B89 / 2947 | reason code와 remediation 사용자 안내 | FR-308 | 부분 | E15/E22 | 알려진 코드 한국어 안내 있음. 모든 provider/runtime 원인·cache age/risk/freshness 상세 remediation 불완전 |
| B90 / 2948 | benign corpus의 지속적인 실제 false-positive 측정 | FR-113 평가 | 부분 | E10, `benchmarks/` | fixture/평가 harness 존재. 운영 corpus·라벨·실제 모델의 검증된 FPR와 지속 추세는 없음 |
| B91 / 2949 | appeal→새 digest/정책 fresh scan→원본 history 보존 | FR-406 | 완료 | E21 | quota/응답 유실/실패·동일 key·cross-mode 미소비 회귀. validator 판정 자체를 뒤집는 자동 승인은 아님 |
| B92 / 2975–2985 | Stage A Compose API/PG/worker/object store/testnet/keys/CLI 운용 | 다수 FR 조합 | 부분 | E08/E12/E18 | 설정·기존 일부 CI 존재. static-only control worker 기본값, MinIO 미구축·Base Sepolia 현재 미검증. 2–4 dynamic worker 운용 미입증 |
| B93 / 2987–2996 | Pilot managed PG replica·broker·K8s Jobs·tenant policy 운영 | 확장 계획 | 부분 | E02/E08/E18 | API/worker·policy·S3 adapter·multi-RPC primitives 있음. 관리형 replica/broker/K8s 배포는 없음 |
| B94 / 2998–3007 | Production 다지역·microVM·독립기관·mirror/checkpoint | 확장 계획 | 미완료 | E08/E18 | 설계 설명만. action-receipt checkpoint는 독립기관 transparency network가 아님 |
| B95 / 3009–3027 | scan row와 publish의 dual-write 원자성 | FR-405 | 완료 | E03 | SQL 행이 곧 durable queue라 외부 publish 자체 없음. transactional outbox는 chain에 사용; 제시 설계와 동등 목적의 대안 |
| B96 / 3029–3035 | stage별 queue/concurrency/DLQ | FR-404 확장 | 미완료 | E03/E08 | scan/preparation/chain queue는 있지만 resolve/static/AI/sandbox별 독립 큐 아님 |
| B97 / 3037–3047 | 중복 delivery 결과 재사용·lease takeover·세대 fence | FR-405/404 | 완료 | E03 | scan/preparation job 단위. scannerVersion+stage 입력으로 단계별 재사용하는 요구는 B96/B77 |
| B98 / 3048–3049 | content-addressed upload·chain payload/tx dedup | FR-202/405 | 완료 | E06/E13 | encrypted tenant-bound hashkey와 raw tx-before-send. orphan cleanup 별도 B118 |
| B99 / 3066–3079 | 서로 다른 source context의 공용 digest deep-scan single-flight | FR-007 세부 | 부분 | E03/E09 | 같은 tenant/release/policy의 valid result 재사용만. in-flight 다른 key·cross-registry future 공유 없음 |
| B100 / 3081–3104 | PG indexes/pool + replica/partition/archive/shard | 운영 확장 | 부분 | E03/E04 | pool10 및 일부 index/단일 primary. read replica/month partitions/archive/실제 sharding 없음; metadata에 report 요약도 저장하므로 URI만은 아님 |
| B101 / 3117,3123 | 암호화 object·package 비포함 안전한 key | FR-403 | 완료 | E06 | AES-GCM+SDK SSE 헤더/conditional create 실제 local HTTP 검증. 실제 cloud encryption 운영 확인은 별도 |
| B102 / 3118–3122 | bucket 불변/versioning·lifecycle·보존·짧은 presign·malware IAM 분리 | FR-403 운영 | 부분 | E06/E18 | overwrite 차단·private download로 presign 미발급. bucket versioning/30–90일 lifecycle·계정분리·복원 실제 검증 없음 |
| B103 / 3125–3143 | Redis 재생성 cache·rate limit·lock·flush 복구 | 운영 확장 | 미완료 | E03/E15 | Redis 도입 안 함(SQL queue/로컬 cache 대안). Redis라는 이름 없이 분산 lock/flush 복구 완료라고 해석하지 않음 |
| B104 / 3149–3153 | 일일/size quota 및 publisher burst/emergency 우선순위 | FR-404 확장 | 부분 | E02/E03/E09 | 일일/대기/size quota 구현. publisher burst·deep running slot·emergency priority는 없음 |
| B105 / 3157 | queue age SLO 초과 시 low-priority 접수 지연 | 운영 확장 | 미완료 | E03 | 고정 maxQueuedScans 429만 존재; age/risk별 admission 제어 없음 |
| B106 / 3158–3159 | deterministic critical/AI quota에 따른 bounded 검사 전환 | FR-113/404 | 부분 | E10 | critical early fail와 ABSTAIN 존재. forensic queue·AI stage만 resumable pending 구현 없음 |
| B107 / 3160 | object-store 장애 시 sandbox 생성량 축소 | FR-404 확장 | 미완료 | E06/E08 | upload 실패는 작업 실패로 처리; 저장소 건강 연동 backpressure 없음 |
| B108 / 3162–3182 | 지역 indexer/signed snapshot/CDN와 revocation fan-out | 확장 계획 | 미완료 | E14/E15 | local fallback interface만; 다지역 운영·fan-out 검증 없음 |
| B109 / 3184–3192 | 정상 PASS batch + 긴급 상태 즉시 chain 확장 | FR-202 확장 | 미완료 | E13/E20 | receipt Merkle batch는 별개. release PASS batch contract/proof 없음 |
| B110 / 3196 | 사용자에게 scan 예상 비용 표시 | 직접 FR 없음 | 미완료 | E02/E22 | stage/status 표시는 비용 견적·실측 비용 아님 |
| B111 / 3197 | scan별 LLM token/input/output 예산 | FR-105/111 | 부분 | E10 scoped | scoped bound/budget 구현. 모든 legacy 경로 실제 비용 계측·운영 provider billing 일치 검증 없음 |
| B112 / 3199 | popularity/risk 기반 deep scan 선택 | 직접 FR 없음 | 부분 | E10 | 위험 tier별 선택은 있으나 인기 기반 스케줄링·제품 deep scan 경로 없음 |
| B113 / 3200 | artifact·execution timeout hard cap | FR-108 | 완료 | E09/E10/E16 | 지원 프로필 기준; daemon/전체 인프라 손상까지 종료 보증 아님 |
| B114 / 3201–3202 | gas ceiling/emergency wallet·기관별 월 비용/품질 | 운영 확장 | 미완료 | E13/E17 | signer nonce 분리 외 비용 ceiling/우선 wallet/월별 집계 없음 |

## 5. 실패·복구 (3206–3428)

| ID / 원문 행 | 원자 요구 | FR 매핑 | 상태 | 증거 | 미충족·판정 범위 |
|---|---|---|---|---|---|
| B115 / 3210–3215,3221–3232 | bounded network timeout·재시도+지수 backoff+jitter | FR-404/405 | 부분 | E03/E06/E12/E15 | RPC/fetch/AI/S3 bounds와 scan 최대3회 exponential backoff 있음. scan jitter 없음; chain outbox는 비종결 장애에 최대회수/backoff 없어 CLI가 재시도 지속 가능. 문서의 각 권장 timeout/resume/providercrossover 전부와 일치하지 않음 |
| B116 / 3234–3263 | retryable/input/security/review 실패 구분과 다른 안내 | FR-404/308 | 부분 | E08/E10/E22 | 코드+retryable/ABSTAIN/DEAD_LETTER와 고정 오류 있음. 정규식 분류가 모든 registry HTTP 원인을 보존하지 않음; 문서 enum 전체 및 remediation은 미완료 |
| B117 / 3265–3273 | provider별 closed/open/half-open circuit breaker | FR-306/404 확장 | 미완료 | E06/E12/E15 | bounded fallback/timeout은 있음. 오류율 기반 breaker 상태·half-open·AI DEFERRED queue는 없음 |
| B118 / 3275–3293 | DLQ details·안전한 승인 재시도 | FR-404 | 부분 | E03/E21 | job attempts/lastError/identity/history·operator retry fence 완료. stage별 eventId/inputDigest/safeReplay DTO·독립 DLQ는 없음 |
| B119 / 3297–3308 | scan 후 chain 실패·응답 유실 시 동일 tx로 수렴 | FR-405/305 | 완료 | E13/E14 | PREPARED/SUBMITTED·raw tx/hash/nonce 저장·receipt 조회/rebroadcast; chain 미확정은 허용 안 함. UI 명칭은 예시와 다름 |
| B120 / 3310–3312 | object 성공/DB 실패 orphan을 grace 후 GC | FR-403 운영 | 미완료 | E06 | adapter는 delete 기능 없음; 자동 orphan 식별·수거 없음 |
| B121 / 3314–3321 | validator 1명 장애 quorum, 2명 장애 보류, stale set 거절 | FR-205–207 | 부분 | E11/E17 | quorum/거절 primitives 검증. signer fan-out은 CLI 실행이며 조직별 가용성·quorum deadline/NTP 모니터 미구현 |
| B122 / 3323–3334 | 키 사고 disable/rotation 및 영향 재검증·conflict 탐색 | FR-211/406 | 부분 | E11/E17/E18 | disable/version+timelock·새 scan primitives. 실제 multisig/HSM 대응·단독 quarantine 영향 분석·conflicting signature 탐색/훈련 없음 |
| B123 / 3336–3342 | head/finalized·orphan replay·block hash 없는 응답 거절 | FR-210/306 | 부분 | E14/E15 | 실제 reorg/hash 검사 완료(B60–62); 이중 DB/UI projection 필드는 B61 미충족. 중복 완료 집계 금지 |
| B124 / 3344–3351 | registry 삭제 후 bytes 보존·digest 검증, 새 source 실패 | FR-002/004/306 | 부분 | E01/E09/E15 | retained source snapshot·immutable Gateway 검증 존재. 재배포 라이선스 운영, mirror origin 증거·보존 SLA 없음 |
| B125 / 3353–3359 | worker에 운영 secret/validator key 금지·job-scoped token·egress 격리 | FR-107/109/403 | 부분 | E08/E09/E17 | candidate container에 키를 전달하지 않고 network 제한. control worker는 DB/evidence/signing config를 공유; short-lived job token 또는 완전 별도 credential host 아님 |
| B126 / 3360–3363 | 침해 node cordon/폐기·그 node scan 재검증·forensics | 운영 보안 | 미완료 | E18 | runbook 일반 안내 외 kernel alert→node 격리→scan 신뢰철회 자동화/훈련 없음 |
| B127 / 3365–3375 | untrusted text·no tools/network·JSON enums·length caps·URL 미실행 | FR-105/106/113 | 완료 | E10/E17 | caller 통제·schema/provider 계약 기준. 모델 의미 정확도/제3자 provider 내부 동작 보증 아님 |
| B128 / 3377–3386 | cache→indexer→RPC fallback, revoke 보존 | FR-306 | 완료 | E15 | 실제 로컬 EVM/failure tests. B63/B82와 중복 |
| B129 / 3386 | break-glass에 사용자/이유/만료/identity 서명 감사 | FR-401/308 확장 | 완료 | E16 | private signed grant, 소모 ledger, 암호화 chained audit. 중앙 WORM/HSM 감사 아님; B79와 중복 |
| B130 / 3392–3398 | chain/DB/evidence/trace/cache RPO·RTO 수치 입증 | 운영 목표 | 미완료 | E18 | local DB restore drill은 있음. 5분/1시간 등 운영 지속복구 수치 측정·SLA 증거 없음 |
| B131 / 3400 | PostgreSQL PITR | 운영 복구 | 부분 | E18 | dump/restore runbook+이전 실제 CI drill. WAL archiving/PITR 운영 및 특정 시점 복원 검증 없음 |
| B132 / 3401 | object versioning와 cross-region 복제 | 운영 복구 | 미완료 | E06/E18 | 설정 권고만; bucket 운영/복구 검증 없음 |
| B133 / 3402 | IaC로 indexer/API 재배포 | 운영 복구 | 부분 | E08/E18 | Compose/Docker 구성은 있음. 재해 시 외부 인프라 provision+키/데이터 복구 IaC/drill 없음 |
| B134 / 3403–3404 | validator encrypted backup/HSM recovery·분기 restore drill | FR-211 운영 | 미완료 | E18 | 절차 필요성 기록만; 실제 기관 키복구·분기 운영 증거 없음 |
| B135 / 3406–3425 | 장애와 악성 구분·risk/cache/freshness/retry 안내 | FR-308/404 | 부분 | E15/E22 | 고정 코드/상태별 안내 존재. 원문의 전 필드/대응 방법을 일관되게 보여주는 메시지 계약 미완료 |

## Main FR 원장에 보낼 권고 (추가 집계 금지)

| 원문 행 / FR | 권고 상태 | 근거와 남은 조건 |
|---|---|---|
| 512 / FR-007 | 부분 | E03 같은 tenant/release/policy valid 결과 재사용은 검증. artifact+policy 기준의 source/다른 release 공용 deep reuse 및 prepared baseline 제약을 함께 공개해야 함 |
| 513 / FR-008 | 부분 | E03 legacy 자동 VERIFIED baseline·수동 지정 시험 통과. prepared Node/OCI baseline은 지원하지 않음 |
| 537 / FR-201 | 완료 | E02/E11/E17 exact versioned policy hash, 다른 mode/정책 재해석 거절. 신규 정책 native 성공 여부와 별개인 binding primitive |
| 538 / FR-202 | 완료 | E05/E11/E13 원문 대신 roots/digests/상태/유효기간/서명 저장 검증 |
| 539 / FR-203 | 완료 | E11/E12 실제 EIP-712 local EVM recovery |
| 540 / FR-204 | 완료 | E11/E12/E13 domain·identity·policy/root·nonce/deadline/set binding/replay tests |
| 541 / FR-205 | 완료 | E11 round별 signer unique 및 signer-bound replay 거절 |
| 542 / FR-206 | 완료 | E11 actual EVM PASS/FAIL 2-of-3. 원문 MVP 요건만, 다른 기관 네트워크는 Main extra |
| 543 / FR-207 | 완료 | E11/E13 deterministic code·≤24h·global quarantine·새 증거 필요 테스트 |
| 544 / FR-208 | 완료 | E11 terminal exact release, 다른 policy로 복원 불가 테스트 |
| 545 / FR-209 | 완료 | E11 ABI/storage에 raw report·PII·secret 없음. revert 문자열은 저장소 원문 데이터가 아님 |
| 546 / FR-210 | 부분 | E11/E14 explicit transition events/indexer 구현. wall-clock expiry는 view/syncExpiry이고 자동 expiry tx 운영·Gateway push 구독은 미완료 |
| 547 / FR-211 | 부분 | E11 1일 rotation timelock/disable version 코드 존재. 실제 rotation timelock 운영·Safe 및 승인/복구 전체 검증 미입증; disable 테스트만으로 전체 governance 완료 처리 안 함 |
| 548 / FR-212 | 완료 | E11/E12 nonproxy bytecode와 local 배포. 최신 Base Sepolia 공개 배포는 별도 B49 미충족 |
| 571 / FR-403 | 완료 | E06 raw evidence operator/admin 권한·tenant AES-GCM·접근 audit 테스트. bucket WORM/운영 보존은 독립 extra |
| 572 / FR-404 | 부분 | E03 scan/preparation retry/max3/DLQ/수동재처리 검증. E13 chain action 비종결 장애에는 retry 상한/backoff/DLQ 부족, stage별 큐도 없음 |
| 573 / FR-405 | 완료 | E03/E13 같은 scan key 및 domain-bound chain action hash+raw tx 재송신 검증 |
| 574 / FR-406 | 완료 | E21 original immutable history·fresh scan linkage·실패 rollback·모드 mismatch slot 미소비 검증 |
| 575 / FR-407 | 완료 | E20 선택 receipt batch Merkle anchor·tenant ACL·confirmation/reorg local EVM 테스트. 실제 운영 action 원장 채택이나 release PASS batch와는 다름 |

## FR 외 추가 독립 요구 후보 — BE stable ID

이 표만 extras의 후보 원장이다. 위 B행은 근거/coverage이며 합산하지 않는다. 이 표에서도 Main/Frontend 소유 중복은 아래 별도 목록으로 제외했다. `부분`을 0.5로 바꾸지 않는다. 정확률은 **완료/N**, 부분은 **부분/N**로 따로 계산하되 최종 N은 Main의 전역 중복 제거 후 확정한다. 인프라 수단의 선택안은 명시했다.

| ID / 원문 행 | 독립 요구 | FR 관계 | 상태 | 증거 | 남은 것 |
|---|---|---|---|---|---|
| BE-001 / 972–974 | namespace+locator 식의 Tool ID | FR-003/004를 넘는 exact 식 | 부분 | B01/E01 | SHA-256 namespace 구분으로의 일관된 계약 |
| BE-002 / 999–1003 | UUIDv7 scan ID | 없음 | 미완료 | B03/E03 | UUIDv4 대체/마이그레이션 |
| BE-003 / 1011,1063 | policy alias 해석 입력 | FR-201 hash와 구별 | 부분 | B05/E02 | alias→고정 hash resolution API |
| BE-004 / 1066 | callbackUrl 완료 통지 | API 예시 기능 | 미완료 | B08/E02 | 인증/SSRF-safe callback 정책·실행 |
| BE-005 / 1089–1099 | 실제 stage별 진행률 조회 | FR-402 단순 검색보다 확장 | 부분 | B10/E02/E03 | 단계 상태 및 측정된 진행률 |
| BE-006 / 1199–1211 | stage event의 독립 versioned envelope | FR-401 trace와 구별 | 부분 | B15/E07/E08 | model/scenario/step 중복키 계약 |
| BE-007 / 1218–1226 | tool registry namespace/locator uniqueness 모델 | SQL 예시의 고유관계 능력 | 부분 | B16/E04 | JSON metadata 외 registry uniqueness 제약 |
| BE-008 / 1269–1282 | finding fingerprint unique/index 조회 | FR-104 SBOM과 별개 | 부분 | B20/E04 | 전용 finding 원장과 index |
| BE-009 / 1326–1338 | client별 admission 결정 원장 | FR-401 trace와 구별 | 부분 | B24/E04/E15 | client hash·cache age·partitioned 영향 조회 |
| BE-010 / 1388 | 별도 semantic NFC representation | FR-005 원본 보존과 구별 | 미완료 | B30/E05 | 원본과 분리된 정규화 계약 |
| BE-011 / 1390 | volatile metadata 별도 hash layer | FR-006 필수 security hash와 구별 | 미완료 | B30/E05 | volatile/security layer 구분 |
| BE-012 / 1393 | remote schema ref 금지/고정 | FR-006보다 추가 입력경계 | 완료 | B32/E10 | 금지 전략 시험 완료, 원격 fetch 대안 미선택 |
| BE-013 / 1667–1672 | package owner/repository 불일치 신호 | FR-003 단순 provenance 기록보다 확장 | 미완료 | B44/E09 | 신뢰근거와 mismatch 판정 |
| BE-014 / 2100,2287 | equivocation 증거 제출·event | FR-205 중복표 거절과 구별 | 미완료 | B48/E11 | 상충서명 탐지/공개 event |
| BE-015 / 2196–2208 | PolicyRegistry URI/tier metadata | FR-201 hash binding보다 확장 | 부분 | B52/E11 | URI/tier/폐기시각 metadata |
| BE-016 / 2293–2297 | validator별 서로 다른 구현 프로필 | FR-206 quorum보다 확장 | 부분 | B136/E17 | A/B/C 독립 구현·규칙 집합 |
| BE-017 / 2317–2333 | finding 단위 선택 공개 Merkle proof | FR-202 root 저장보다 확장 | 부분 | B57/E05 | 현재 파일 leaf에서 개별 finding leaf로 구분 |
| BE-018 / 2422,3338–3340 | optimistic/finalized 이중 projection | FR-210 event보다 확장 | 부분 | B61/E14 | 별도 DB/UI 필드·pending confirmation |
| BE-019 / 2473 | OpenZeppelin ECDSA 구현 사용 | 명시 구현 수단 | 부분 | B67/E11 | 검증된 library 사용/동등성 독립 감사; 단순 함수 교체 제안 아님 |
| BE-020 / 2866 | digest별 설치 cache | FR-007 결과 재사용과 구별 | 부분 | B70/E09 | 공유 설치 layer cache |
| BE-021 / 2867–2869 | quick/deep 작업 프로필 분리 | FR-108 cap보다 확장 | 미완료 | B71/E10 | 실제 선택/queue/scenario 시간 프로필 |
| BE-022 / 2870,3151 | tenant running concurrency quota | 일일/대기 quota와 구별 | 부분 | B72/E03 | running slot 원자 제한 |
| BE-023 / 2872 | worker host 일회성 폐기 | FR-107 후보 일회성보다 확장 | 미완료 | B74/E08 | container cleanup과 별개인 worker host disposable lifecycle |
| BE-024 / 2874,3051–3064 | backlog/age/token 기반 autoscaler | 없음 | 미완료 | B75/E19 | 관측 신호→scale 제어·실제 운영 검증 |
| BE-025 / 2888–2895 | model/prompt/policy/input keyed AI cache | FR-007 deep result cache와 구별 | 미완료 | B77/E10 | semantic 단계 cache와 정확한 invalidation |
| BE-026 / 2911 | validator scanner version 운영 inventory | FR-201 policy version보다 확장 | 부분 | B81/E17 | 기관별 scanner 실행 버전 대조 |
| BE-027 / 2913,3227 | quorum deadline와 서명 backoff scheduler | FR-206 count보다 확장 | 부분 | B80/E17 | 자동 deadline·팬아웃·지연 상태 기록 |
| BE-028 / 2921 | cache 만료 jitter | FR-306 grace보다 확장 | 미완료 | B83/E15 | 동시 만료 분산 |
| BE-029 / 2922 | 동일 admission 요청 single-flight | FR-306 cache보다 확장 | 미완료 | B83/E15 | future 공유; 현재 pending fence는 대체 아님 |
| BE-030 / 2925 | RPC fallback process quota | FR-306 fallback보다 확장 | 완료 | B85/E15 | 고정 quota 대안 검증; token bucket 자체 미선택 |
| BE-031 / 2932 | 유효기간 기반 PASS 자동 갱신 | FR-206 fresh quorum보다 확장 | 미완료 | B86/E13 | 갱신 스케줄러 |
| BE-032 / 2934,2463 | quorum 서명 단일 tx aggregator | 선택 Pilot 대안 | 미완료 | B65/E13 | aggregator와 contract batch; 현재 개별 tx |
| BE-033 / 3015–3027 | scan queue dual-write 원자성 | FR-405 중복과 다른 장애 조건 | 완료 | B95/E03 | SQL 동일 row queue 대안 검증, 외부 queue publisher는 미선택 |
| BE-034 / 3029–3035 | stage별 독립 queue | FR-404 전체 job DLQ보다 확장 | 미완료 | B96/E08 | resolver/static/AI/sandbox/evidence/validator 큐 분할 |
| BE-035 / 3035 | stage별 concurrency | BE-034와 다른 제어 | 미완료 | B96/E08 | 각 stage 자원 상한 |
| BE-036 / 3035,3277 | stage별 DLQ 및 safeReplay metadata | FR-404 job DLQ보다 확장 | 부분 | B118/E03 | job DLQ만 있고 stage/inputDigest/event envelope 부족 |
| BE-037 / 3077–3079 | scan in-flight single-flight | FR-007 이미 유효한 결과와 구별 | 미완료 | B99/E03 | 다른 request key의 같은 digest future 공유 |
| BE-038 / 3092 | Dashboard read replica | 운영 확장 | 미완료 | B100/E03 | 읽기 분리·replica lag 처리 |
| BE-039 / 3093 | scan/event 월 partition | 운영 확장 | 미완료 | B100/E04 | partition migration·유지보수 |
| BE-040 / 3095 | DB connection pool | 운영 확장 | 완료 | B100/E03 | pg Pool max10 실제 PG CI. 대규모 최적화는 별개 |
| BE-041 / 3098–3104 | tenant/namespace sharding | 선택 Production 대안 | 미완료 | B100/E04 | 실제 routing/rebalance/canonical projection 검증 |
| BE-042 / 3117 | object-store server-side encryption | FR-403 앱 암호화보다 확장 | 부분 | B101/E06 | SDK SSE 헤더 검증만; 실제 cloud/KMS 적용·복구 미검증 |
| BE-043 / 3118 | immutable/versioned bucket | FR-403 역할제한보다 확장 | 부분 | B102/E06/E18 | conditional create만 검증; versioning/WORM 실제 bucket 없음 |
| BE-044 / 3121 | 짧은 presigned download TTL | 선택 전달 방식 | 미완료 | B102/E06 | 현재 인증 API 경유만, presign 발급은 하지 않음 |
| BE-045 / 3122 | malware artifact와 일반 bucket 계정/IAM 분리 | 운영 보안 | 미완료 | B102/E18 | 실제 계정·권한 분리/접근 시험 |
| BE-046 / 3123 | object key path traversal 방지 | 입력경계 | 완료 | B101/E06 | package 이름 대신 제한된 hash key 검증 |
| BE-047 / 3125–3136 | Redis 재구성 가능한 cache 운영 | 선택 인프라 | 미완료 | B103/E03/E15 | SQL/local 대안 사용; Redis flush 복구 없음 |
| BE-048 / 3143 | release별 전역 stateVersion stale-write fence | FR-307 push보다 확장 | 부분 | B84/E15 | local epoch/terminal journal만, projection 전역 version 없음 |
| BE-049 / 3149 | tenant 일일 scan quota | admission control | 완료 | B104/E03 | transaction·동시 요청/재시도 검증 |
| BE-050 / 3152 | publisher burst quota | admission control | 미완료 | B104/E03 | publisher 기준 속도/버전 상한 |
| BE-051 / 3153 | emergency rescan priority | admission control | 미완료 | B104/E03 | 우선순위 큐/공정성 정책 |
| BE-052 / 3157 | queue age 기준 접수 지연 | backpressure | 미완료 | B105/E03 | maxQueued 429만 존재 |
| BE-053 / 3158 | static critical의 forensic queue 전환 | 선택 backpressure | 미완료 | B106/E10 | early fail은 있으나 forensic queue 없음 |
| BE-054 / 3159 | AI quota 소진 시 단계만 pending·resume | backpressure | 부분 | B106/E10 | ABSTAIN/전체 job 결과만, 단계 재개 없음 |
| BE-055 / 3160 | object-store 장애 연계 실행량 축소 | backpressure | 미완료 | B107/E08 | 업로드 실패와 worker admission 연계 없음 |
| BE-056 / 3196 | scan 비용 사전 안내 | 비용 운영 | 미완료 | B110/E22 | 비용 견적·실측 피드백 |
| BE-057 / 3199 | popularity 기반 deep-scan 선택 | 비용 운영 | 미완료 | B112/E10 | risk tier와 달리 popularity 수집/스케줄 없음 |
| BE-058 / 3201 | chain gas ceiling | 비용 운영 | 미완료 | B114/E13 | tx 비용 상한·보류 상태 |
| BE-059 / 3201 | emergency 전용 priority wallet | 운영 격리 | 미완료 | B114/E13 | 일반 relayer와 분리 운용 |
| BE-060 / 3202 | validator 월별 비용/품질 측정 | 운영 평가 | 미완료 | B114/E17 | 기관별 비용/판정 품질 지표 |
| BE-061 / 3211,3221–3230 | 모든 외부 작업별 total deadline 정책 | FR-404 retry와 구별 | 부분 | B115/E06/E12 | 주요 호출은 bounded, 문서 stage/서명/전체 작업 deadline 일관성 부족 |
| BE-062 / 3232 | retry jitter | FR-404 retry보다 확장 | 미완료 | B115/E03 | exponential scan backoff에 jitter 없음 |
| BE-063 / 3265–3273 | RPC circuit breaker | FR-306 fallback과 구별 | 미완료 | B117/E15 | closed/open/half-open 상태 없음 |
| BE-064 / 3265–3273 | AI circuit breaker | FR-404 실패분류와 구별 | 미완료 | B117/E10 | provider별 오류율/half-open/DEFERRED 없음 |
| BE-065 / 3310–3312 | grace-period orphan object GC | 부분 실패 보상 | 미완료 | B120/E06 | object 참조 대조/삭제 큐 없음 |
| BE-066 / 3319 | validator NTP/clock-skew 모니터 | 운영 보안 | 미완료 | B121/E17 | deadline 검사만, 시간 동기 감시 없음 |
| BE-067 / 3330–3332 | 침해키 quarantine 영향 조사·재검증 캠페인 | FR-211 disable보다 확장 | 미완료 | B122/E18 | 자동 영향 집계/운영 drill 없음 |
| BE-068 / 3357–3358 | worker job-scoped 단기 credential | FR-107 candidate 격리와 구별 | 미완료 | B125/E08 | host worker가 DB/evidence/signing 설정 공유 |
| BE-069 / 3360 | kernel 경보 기반 node cordon/폐기 | 운영 보안 | 미완료 | B126/E18 | 자동 격리·운영 검증 없음 |
| BE-070 / 3361 | 침해 node 산출 scan 전체 신뢰철회/재검증 | 운영 보안 | 미완료 | B126/E18 | node→scan provenance/사고 orchestration 없음 |
| BE-071 / 3362 | 침해 후 base/runtime 재빌드 | 운영 복구 | 부분 | E18/CI builder | CI image build는 존재. 침해 대응 발동·검증 훈련 없음 |
| BE-072 / 3363 | 격리 forensic snapshot | 운영 보안 | 미완료 | B126/E18 | 계정 분리 보관·접근/삭제 절차 없음 |
| BE-073 / 3386 | 서명 break-glass 감사 | FR-308/401보다 확장 | 완료 | B129/E16 | private reason/identity/expiry/1회 소모 시험; normal verdict 유지 |
| BE-074 / 3395 | DB RPO≤5분/RTO≤1시간 달성 | 운영 목표 | 미완료 | B130/E18 | dump drill은 수치 SLA 증거 아님 |
| BE-075 / 3396 | evidence RPO≤15분/RTO≤4시간 달성 | 운영 목표 | 미완료 | B130/E18 | 운영 측정 없음 |
| BE-076 / 3397 | raw trace RPO≤1시간/RTO≤24시간 달성 | 운영 목표 | 미완료 | B130/E18 | trace 보존·복원 검증 없음 |
| BE-077 / 3400 | PostgreSQL PITR | 운영 복구 | 부분 | B131/E18 | dump/restore는 있음, WAL 기반 특정시점 복원 없음 |
| BE-078 / 3401 | object cross-region replication | 운영 복구 | 미완료 | B132/E18 | 설정/실제 복구 없음 |
| BE-079 / 3402 | IaC 재해 재배포 | 운영 복구 | 부분 | B133/E08 | Compose는 있으나 외부 infra+state+key 복구 drill 없음 |
| BE-080 / 3403 | validator key encrypted/HSM recovery | 운영 복구 | 미완료 | B134/E18 | 실제 키복구 절차·훈련 없음 |
| BE-081 / 3404 | 분기별 restore drill | 운영 복구 | 미완료 | B134/E18 | 단발 CI empty DB restore와 반복 운영은 다름 |
| BE-082 / 1228–1237 | artifact digest PK·size/media/object/retention 제약 모델 | SQL 예시 metadata 능력 | 부분 | B17/E04 | 현재 JSON metadata, 별도 불변 artifact relation/retention 제약 없음 |
| BE-083 / 1239–1249 | release→tool/artifact/baseline 관계 제약 모델 | SQL 예시 FK 능력 | 부분 | B18/E04 | exact ID는 있으나 명시 FK와 release baseline relation 없음 |
| BE-084 / 1100–1101 | scan 시작/전체 deadline 조회 | FR-402 조회보다 확장 | 부분 | B10/E03 | created/updated timestamp는 있으나 startedAt/deadlineAt 계약 없음 |
| BE-085 / 2873 | timeout 뒤 process tree/network namespace 정리 검증 | FR-108 시간 cap보다 확장 | 부분 | B74/E10/native tests | container 삭제는 있음. 잔여 process/namespace 누수 전수 확인·host 침해 cleanup proof 없음 |

### 전역 중복·비집계 지시

- Main extra 소유와 중복: B34의 PyPI/Sigstore, B47 기관 독립, B50 다중 chain, B74/B94 stronger isolation, B94/B108 다지역/mirror, B102 retention, B109 PASS batch, B111 tier/token 설계. **이 표에 extra ID를 다시 부여하지 않았다.** main의 retention 원장이 archive/lifecycle도 묶는다.
- B29/B31 원본 canonical/hash, B43/B45 source bytes, B54–56/B58/B62 chain primitives, B78/B88 AI-only 제한, B91 appeal, B97 idempotency, B113 hard caps, B119 saga tx recovery, B127 prompt 경계는 FR cross-reference로만 사용한다.
- BE-009/018/028/029/048/073은 Frontend/Gateway 감사에 같은 항목이 있을 수 있다. Main은 동일 원문 요구를 한 ID에 귀속한다. URI/schema/example 자체를 반드시 구현할 제품 요구로 볼지(특히 BE-004/007/015/019/032/044/047)는 원문의 성격을 유지한 채 **명시적 대안/예시 제외 집계**로 확정할 수 있다. 조용히 누락하지 않는다.
- 가정된 사용자 수/QPS/worker 대수나 FMEA RPN 숫자는 추가 미완료 하드 요구로 만들지 않았다. latency/availability/2-RPC recovery NFR 수치는 Main 소유다.

## Coverage note — 설명·예시·대안·중복을 버리지 않음

| 원문 행 | 성격 | 처리 |
|---|---|---|
| 965–968,977–982 | 식별자 취지·예 | B01–04로 대조; 예시 문자열 자체를 구현 기능으로 세지 않음 |
| 1013–1193 | API payload/response 예시 | B05–14; envelope/필드 이름 차이는 기록하고 callback/progress 등 실제 없는 능력은 미충족 처리 |
| 1211 | Redis/BullMQ와 Kafka/NATS 대안 | SQL durable queue가 현재 선택(B95). broker 도입 완료 아님(B96/B103) |
| 1213–1348 | PostgreSQL 논리 SQL·index 예시 | B16–25; JSON 문서 저장 대안의 제약/검색 부족을 명시. 예시 테이블 이름만 없다고 전체 API 미구현으로 판정하지 않음 |
| 1358–1378 | report 파일 tree 예시 | B27/B57. runtime profile별 파일명이 달라도 proof 기능은 인정; 모든 제시 leaf가 존재한다는 주장은 하지 않음 |
| 1395–1419 | canonical tool JSON 예시 | B29–32/B46. auth-aware scope는 별도 미충족 |
| 1422–1433,1434–1507 | 아키텍처 원칙·그림 | B33–36. Redis/MinIO/PyPI/Sigstore가 그림에 있다는 이유로 구현으로 표시하지 않음 |
| 1509–1642 | control/data/trust 설명·3 sequence | B37–41. 각 기능 FR 완료를 이 그림 때문에 다시 추가 집계하지 않음 |
| 1644–1663 | plugin interface 예시 | 함수 dispatch 대안 B42. PyPI/fetchPlan 부족 유지 |
| 1696–1708 | auth-aware Production 확장 | B46 부분. MVP 무인증 한 프로필의 성공을 모든 권한 scope로 확장하지 않음 |
| 2093–2122 | chain 한계·DB 정당성·Registry/Sigstore/ERC 관계 설명 | 정책/발표 제약이며 기능 분모 제외. 실제 provenance 연동은 B34, 기관 전제는 B47 |
| 2137–2143 | 자체 체인·토큰·과도한 upgrade 제외 | 기존 EVM/3-contract 선택에 부합. 새 consensus 구현 요구 아님 |
| 2149–2209 | Solidity interface 예시 | B51–52. ABI 함수명/구조 차이와 실제 누락 metadata를 구분 |
| 2212,2293–2299 | 데모 독립 키와 실제 독립기관 구별 | B47/B53/B121. 세 키를 탈중앙 운영 완료로 세지 않음 |
| 2214–2287,2301–2309 | 상태/replay/quorum 반복 | B54–56/B59/B68에 FR 매핑; 표/의사코드별 중복 집계 없음 |
| 2311–2313,2335–2344 | 긴급격리·Merkle의 장단점 | B55/B57 설명. inclusion proof가 행동 진실 증명이라는 주장 금지 |
| 2386–2418 | submitAttestation 의사코드/정책별 모델 선택 | 실제 policy-scoped V2를 B54/B59로 대조. 단순 pseudocode를 구현 코드보다 우선하지 않음 |
| 2444–2457 | DB/Rekor/chain 비교 | 설명. 새로운 세 저장소를 전부 구현할 요구로 읽지 않음 |
| 2463–2467 | 선택적 aggregator/bitmap/Merkle checkpoint | aggregator 미적용 B65, bitmap 미적용(3-validator mapping 사용), release PASS batch B109. 현재 취약점 수나 완료 수로 둔갑시키지 않음 |
| 2471–2482 | 보안 checklist | B66–69와 replay/quorum rows 매핑. deterministic 회귀를 property fuzz로 부르지 않음 |
| 2825–2835,2854–2862 | 병목 축·원인 설명 | 운영 검증 항목 도출 배경. 설명 자체를 성능 달성으로 세지 않음 |
| 2837–2852 | 12개 병목/대응 목록 | sandbox B70–75, AI B76–78, dedup B99, validator B80–81/B121, RPC B63/B117/B128, lag B60–62/B84, hot key B82–85, registry B124, object B107/B120, policy precompile는 TS 정책 대안(E02), false-positive B88–91, escape B125–126 |
| 2914 | 장기 validator rotation | B53/B68 중복. 실제 기관 운영까지 완료 아님 |
| 2934 | 정상 signature batch 가능성 | B65/B109 중복(미적용) |
| 2951–2965 | FMEA 상대 점수·배포통제 위험 | 점수는 실측이 아님. Gateway 조직 강제설정/signed config·HSM·microVM는 미입증(B94/B122/B125); 보고서 변조는 B27. 별도 수치 달성으로 집계 안 함 |
| 2967–3007 | 단계별 roadmap | Stage A/B/C를 B92–94에 각각 보존; Pilot/Production을 이유 없이 감사에서 제거하지 않음 |
| 3051–3064 | scaling signal·KEDA 예시 | B75. 수동 process 수 조정은 autoscaling 성공 증거 아님 |
| 3098–3104 | shard 대안·공통 projection 원칙 | B100 및 B26/B62. shard 구현 안 했으므로 다중 shard 일관성 달성 주장 안 함 |
| 3108–3115 | storage key 예시 | B98/B101. 실제 key는 tenant+root hash; 예시 zstd 경로·압축은 미적용 |
| 3184–3192 | 체인 규모 확대의 3개 대안 | 현재 직접 attestation만 구현; B109는 제안 3의 미구현 상태 보존 |
| 3206–3232 | 실패 원칙·권장 timeout 숫자 | B115; hard timeout 존재와 권장값/재시도전략 일치를 분리 |
| 3275–3293 | DLQ JSON 예시·manual host 실행 금지 | B118; operator retry는 worker 경로. candidate를 사용자 PC에서 실행하는 복구 절차는 추가 안 함 |
| 3295–3342 | Saga/validator/reorg 반복 | B119–123 및 B54–62에 연결; 새 완료 건수로 합산하지 않음 |
| 3388–3425 | 권장 DR 목표와 오류 메시지 예시 | B130–135. 예시 RPO/RTO를 실제 서비스 수치로 인용하지 않음 |
| 각 범위의 빈 행·구분선·제목(1420–1423,1710–1711,2483–2485,2967–2970,3203–3208,3426–3428 등) | 구조 텍스트 | 모두 읽음; 독립 구현 요구 없음 |

## 다음 담당자에게 남기는 결론

핵심 exact identity, 비동기 SQL queue, 암호화/Merkle 증거, 독립 검증 CLI, EIP-712/2-of-3/긴급격리, fail-closed Gateway는 **로컬·제한 프로필의 작동 증거가 있다**. 반면 이 문서 전체는 그보다 넓다. 실제 독립기관·Base Sepolia 최신배포·외부 모델 품질, step별 orchestration, circuit breaker/chain retry backoff, autoscaling, 운영 credential 분리, versioned cloud storage/PITR/DR 수치가 남아 있다.

특히 **chain queue 재시도 제한 부재(B115)**, **worker의 job-scoped credential 분리 부재(B125)**, **독립기관/키 복구 미입증(B47/B122/B134)**를 운영 준비 완료 주장 전에 해소해야 한다. 구현 권한은 이번 감사에 포함하지 않았으므로 이 문서는 수정 작업이나 외부 자원 생성을 시작하지 않는다.
