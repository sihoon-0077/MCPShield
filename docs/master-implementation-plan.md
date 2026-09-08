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

### 현재 검증 경계

- 새 통합 `391a7825ec7dc0f49f11bc543c4bbf9e994b8d86`의
  [CI 34279690606](https://github.com/sihoon-0077/MCPShield/actions/runs/34279690606)를 dispatch했다.
  최초 확인은 pending(작업 배정 전)이며 성공/실패 결과는 아직 없다. 앞선 push 검증과 같은
  concurrency 그룹을 사용하므로 중복 실행 결과를 합산하지 않는다. `391a782`는 OCI UI가
  참조하는 pure binding/descriptor/snapshot 3파일을 standalone dashboard 이미지에도 포함한다.
  `a38ef4a`는 AI 출처 미제공·모델 품질 미측정을 합성 응답 사용으로 추정하지 않도록 수정했고
  실제 API/BFF 및 SSR 회귀 1개 통과. 새 공개 배포·서명된 최종 산출물은 아직 아니다.
- `bb87dea` Main 전체 `npm test` 성공(Security 107 통과·18 Linux skip,
  dashboard 23 통과, backend/Gateway/replay/MCP stdio/live smoke 성공), `npm run build` 성공.
  이어서 `d7b909b`는 실제 OCI resolver→worker→독립 단일키 validator CLI 4개→V2 정족수→
  정상 paginated MCP 실행·별도 Gateway 프로세스 2개의 폐기 이미지 create/start 0건을
  확인하는 Linux 전용 전체 테스트를 추가했다. 공통 프로세스 도우미는 기존 npm 테스트와
  재사용하며 Main portable 3 통과·Linux 2 skip. 실제 Linux 성공은 아직 증명되지 않았다.
  `85c246f` OCI 준비 UI·정책 유형 매칭·private strict config export 통합 후 dashboard
  24개와 production build 통과. 실제 API/BFF/worker 연결은 합성 inspector의 ABSTAIN으로
  검사했으며 브라우저 시각 QA나 실제 OCI 실행 증거가 아니다.
  `a928b9b`는 실패했던 Gateway fixture build/save/수동 archive 변환을 삭제하고 공통
  never-started approved native export를 사용한다. 기존 uid/network/cap/seccomp/env/read-only,
  signed cache/RPC/긴급 1회/EOF/변조 검사는 유지했다. Main OCI 회귀 7 통과·Linux 1 skip.
  새로운 두 OCI Linux CI 단계를 순차 추가하고 전체 job 시간 상한을 55분으로 조정했다.
  원본 `mcp/main`은 `6aa370285154f683989f2bf9b219bd2c052e6cee` 유지.
- [Linux CI 34277348109](https://github.com/sihoon-0077/MCPShield/actions/runs/34277348109),
  `24fa66e`: **종료·전체 실패**. PostgreSQL·Node 24 성공. Node 22 일반 test/build,
  실제 npm closure, prepared Gateway, OCI native import/관측, prepared scan→독립 단일키
  validator→V2→두 Gateway는 성공했다. OCI Gateway는 후보 실행 전 fixture Docker build에서 실패했다.
  별도 OCI Trivy 실패는 실제 Trivy 0.74.0의 CycloneDX **1.7**이 허용 목록 밖인 것이 확인됐다.
  실제 report identity 일치·Results 2개·SBOM components 169개는 진단에서 확인했지만
  package coverage 완료를 뜻하지 않는다. `f36927b`는 공식 1.7 component 필드 호환성만 추가하고
  unknown version/변조된 필드/정확한 package version 누락은 계속 거부한다. Linux 재통과는 미검증이다.
  `signed-image` job `102236056851`은 실제 non-root 이미지 웹·judge·legacy/modern HTTP MCP
  smoke 및 취약점/라이선스 inventory/SBOM 검사에 성공했다. 이미지
  `sha256:b969d301c0389aa9eb6f76fd83d84cb2698debd536691d8d0e2af9740be6f9ec`,
  앱 의존성 248개·HIGH/CRITICAL 0·SBOM checked. upstream 실패로 **서명·attestation 검증·
  이미지 보관은 skipped**, 새 공개 배포도 아니다. 앞선 ECONNREFUSED는 이번에는 재현되지 않았다.
- `63da09d`는 OCI validator가 API의 자기검증 결과 대신 자신의 native trust와 새 전체 스캔을
  얻고, 독립 scan ID·root 및 결정론적 finding 범위를 대조한 뒤 기존 V2 서명 경로를 사용한다.
  `36aea06`은 비동기 검증 뒤와 서명 payload 반환 직전에 만료를 다시 검사한다.
  Main validator/API 관련 17개 및 만료 회귀 포함 validator 11개 통과. 실제 OCI Linux
  전체 서명·quorum·Gateway 연결은 후속 검증이며 LOCAL_CONTRACT_TEST는 외부 AI 품질 증거가 아니다.
- `d7beb04`는 여러 tools/call을 묶은 원문 batch의 **전달 직전** 모든 ALLOW lease를
  wall clock·monotonic clock으로 재검사한다. 뒤 call을 기다리는 동안 앞 call의 승인이
  만료되면 부분 전달 없이 frame 전체를 거부한다. 기존 긴급 승인 최종 검사는 유지한다.
  `be88f02`·`a4abd6c`의 OCI safe/canary source fixture는 승인 base native export를 재사용하며
  numeric/UUID request ID를 지원한다. Main Trivy·fixture·실제 Gateway 만료 관련 10 통과·
  Linux 2 skip. CI에 지원 프로필의 정상/악성 독립 재스캔 검사를 추가했지만 아직 실행 결과는 없다.
  현재 후속 commit 전체가 `24fa66e` 이미지에 포함된 것으로 해석하지 않는다.
- `85a2378`은 OCI pure policy를 scanner 판정에 연결했다. 정확한 원본·실행 identity·관측 effects·
  Trivy/SBOM·두 AI 역할의 근거를 재구성하며, 지원되는 결정론적 유출은 FAIL, 제한된 전체 검사
  충족은 PASS, 나머지는 ABSTAIN이다. `ready:false`를 유지하며 서명/정족수 없이 실행 승인을
  뜻하지 않는다. Main 관련 회귀 20 통과·Linux/PG 5 skip 및 타입 검사 성공.
  `332b73c`는 owned image 정리 실패/DB commit 불확실성을 기존 private recovery record와
  고정 감사 이벤트에 남긴다. 자동 삭제나 완료된 release 상태 변경은 하지 않는다.
  `ed4798c`는 OCI에도 기존 signed cache→조직 indexer→direct RPC와 명시적 1회 긴급 읽기를
  재사용한다. 실제 로컬 이미지 검사는 그대로 선행하며 관련 공통/OCI 회귀 29개 통과.
  실제 OCI Linux 호환 검증은 아직 미실행이다. 리뷰 중 발견한 공통 batch 전달 직전의
  승인 만료 경계는 Front가 별도 재현/수정 중이다.
  [진행 중 CI 34277348109](https://github.com/sihoon-0077/MCPShield/actions/runs/34277348109)는
  이전 `24fa66e`를 검증하며 이 후속 세 commit은 포함하지 않는다. PostgreSQL 완료 성공,
  Node 22/24 일반 테스트 통과 후 build 진행을 확인했다. 같은 SHA의 push run은 dispatch로 취소됐다.
- `c198a20` 통합: OCI API 준비/재스캔 worker가 기존 tenant ACL·queue·lease·CAS를 재사용하고,
  Gateway는 로컬 native CID/rootfs/entrypoint/env와 실행 격리 및 매 호출 서명 승인을 확인한다.
  `LOCAL_CONTRACT_TEST`/`PROVIDER_QUALITY_NOT_MEASURED` 표기를 정책과 공개 요약에 유지한다.
  기존 이미지(BORROWED)는 태그를 추가하거나 삭제하지 않으며, 새 import만 정확한 OWNED UUID
  태그를 정리한다. Docker 조회 실패는 이미지 부재로 추정하지 않는다. 독립 OCI 승인 정책·signer와
  정상/악성 전체 Linux 흐름은 아직 진행 중이다. OCI의 balanced/RPC/emergency 호환도 후속 작업이다.
  Main focused OCI 18 통과·Linux 5 skip, 실제 API HTTP를 통과하는 정상/악성 judge 체험 포함
  release-readiness 5 통과, 타입 검사와 CI YAML parse 성공. `c198a20` 코드 기준 전체 `npm test`
  완료 성공: backend 96 통과·6 skip, Security 105 통과·17 skip, Gateway·dashboard와
  replay/MCP stdio E2E/live smoke 모두 성공. Linux skip은 실제 통과로 집계하지 않는다.
- [Linux CI 34275352307](https://github.com/sihoon-0077/MCPShield/actions/runs/34275352307),
  `229f147`: 전체 run은 완료 실패. Node 24·PostgreSQL 성공. 실제 Docker→EVM quorum→두 Gateway
  차단이 새 초기 상태에서 **10회 연속 통과**했다(job `102229697837`, 각 회 pass 1/fail 0).
  앞선 sink startup 실패는 이번 반복에서 재현되지 않았다. 이는 OCI/실제 외부 AI 승인을 증명하지 않는다.
  Node 22 OCI Trivy의 실제 DB 1,371,783,168 bytes는 새 2GiB 한도를 통과했지만,
  `SBOM_CONVERSION`에서 `OCI_TRIVY_REPORT_IDENTITY_INVALID`로 실패했다.
  정확한 schema 불일치 필드는 아직 미확정이며, `9f317ce`는 원문 없이 schema/version/count만
  진단하도록 보강했다. 형식 허용 목록이나 취약점 gate를 추정으로 완화하지 않았다.
  배포 이미지(job `102229697753`)는 실행 중·OOM 아님 상태에서 smoke가 실패했고,
  로그의 허용된 고정 진단은 `ECONNREFUSED`다. 이것만으로 연결 실패 지점은 확정할 수 없다.
  `e74a85b`는 단계명을 기록하며 실제 API를 통한 같은 judge 계약은 로컬에서 통과했다.
  이미지 서명·다운로드 및 새 Railway 공개 배포는 완료되지 않았다. 원본 데모는 변경하지 않았다.
- `8f48705` Main 전체 `npm test` 성공: backend 88 통과·외부 환경 6 skip,
  Security 103 통과·Linux 16 skip, Gateway 98 통과·Docker 1 skip, dashboard 23 통과,
  replay·실제 MCP stdio E2E·live smoke 성공. 타입 검사 성공; `03318bb` dashboard production build도 성공.
  `b30d9fb`의 외부 full-source 금지와 `30d7751`의 명시적 로컬 테스트 설정 전달을 통합했다.
  최초 통합에서 발견한 synthetic validator fixture 2개 실패는 실제 로컬 semantic engine에
  명시적 선언을 전달해 해소했으며 production 승인 검사를 느슨하게 바꾸지 않았다.
  `03318bb` RPC 조회는 전체 시간 안에서 endpoint별 시간을 배분하고 순수 전송 장애와
  변조/부분 폐기/만료/재편성을 구분한다. Main RPC·실험 진단 회귀 19개 통과.
  `6f9ec77`·`2f18f66`은 cell 집계 즉시 출력·실패 부분 결과·고정 진단·실행 중 작업 정리 후
  provenance를 보존한다. 이는 이전 79,000회 실패의 원인을 확정하거나 전체 재측정을 대체하지 않는다.
  `ff5bc6d` OCI scan은 원본 inventory/Trivy/관측/로컬 AI 계약/불변 binding을 증거 bundle에 연결하고,
  `8f48705`는 export 임시 컨테이너 정리가 확인되지 않으면 proof 성공을 반환하지 않는다.
  OCI portable 15 통과·Linux 4 skip; `afa5e4a`에 실제 composed Linux 회귀를 추가했다.
  독립 OCI 정책과 API/validator/Gateway 연결은 여전히 작업 중이며 scan phase는 승인이 아니다.
  기존 원본 `mcp/main` HEAD는 `6aa370285154f683989f2bf9b219bd2c052e6cee` 유지,
  공개 `/try` GET 200 확인. 새 코드가 Railway에 배포됐다는 의미는 아니다.
- `e399a55`까지 통합. `e5987e4`의 OCI inventory/오프라인 Trivy 단계와 `0dc93c9`의
  원본/파생 identity·고정 실행 정책·OCI 전용 analyzer/critic 계약은 구현됐다.
  binding 생성과 phase COMPLETE만으로 PASS/READY 또는 Gateway 실행을 허용하지 않는다.
  Main OCI portable 10개 통과·Linux 4개 명시 skip, OCI binding 4개 통과,
  prepared/measurement 회귀 11개 통과. 실제 Trivy CLI 검증은 아래 Linux 실패와 구분한다.
- [Linux CI 34272462941](https://github.com/sihoon-0077/MCPShield/actions/runs/34272462941),
  `54d3335`: Node 24·PostgreSQL 완료 성공. Node 22의 일반 테스트/build, 실제 npm closure,
  prepared Docker Gateway(긴급 읽기 1회 포함), OCI import 및 독립 검증자 전체 흐름은 통과했다.
  실제 검증자 재스캔 4회·Gateway OS 프로세스 2개·폐기 이미지 create/start 0건을 다시 확인했다.
  AI는 합성 루프백 계약 서버이며 외부 모델의 분석 품질을 증명하지 않는다.
  native OCI Trivy 단계는 DB snapshot의 `fixture exceeds 1073741824 bytes`로 실패했다.
  전체 run은 실패이며 후속 repeat-demo/signed-image는 skipped다. `922329b`는 신뢰된 DB만
  별도 2GiB streaming 예산으로 수정했고 후보 16MiB·OCI 원본 100MiB 제한은 유지한다.
  `e399a55`는 독립 반복/이미지 진단을 다른 gate 실패 후에도 실행하되 서명·이미지 보관은
  upstream verify와 PostgreSQL 성공 및 앞선 이미지 검사 성공을 계속 요구한다.
  Main 관련 회귀 10개 통과·Linux 2개 명시 skip. DB 수정·이미지 readiness·10회 반복의
  실제 해소 여부는 다음 Linux 실행으로 판단한다.
- [Linux CI 34270393788](https://github.com/sihoon-0077/MCPShield/actions/runs/34270393788),
  `105f12f`: Node 22·24·PostgreSQL 세 job 완료 성공. 실제 prepared 회귀는
  검증자 재스캔 4회, 서로 다른 Gateway OS 프로세스 2개, 폐기 이미지 create/start 0건을 확인했다.
  Docker Compose와 Grafana 익명 접근 거부·dashboard provisioning·실제 exporter→collector→Prometheus
  지표 수집 및 6개 panel query 검증이 통과했다. 주입한 지표는 명시적 SYNTHETIC_MOCK다.
  job `102210667857` 로그의 결과를 확인했으며, 이 실행에는 새 OCI review/binding 코드는 없다.
  후속 두 job은 실패했다. 10회 반복은 첫회 safe sandbox의 sink startup timeout으로 ABSTAIN,
  signed-image는 첫 judge session POST의 503으로 실패했다. 최신 배포 이미지 서명·취약점 단계는
  도달하지 못했으며 전체 CI는 실패다. `03a8cce`는 web 준비와 API demo route 준비를 분리해
  상태 변경 없는 GET으로 확인하고 subprocess 예외를 고정 코드로 제한한다. sink의 실제 HTTP
  readiness 및 bounded Docker 진단도 추가했다. 두 실패의 실제 해소 여부는 다음 Linux 실행으로 판단한다.
- `f6bdc69`·`59a7fe1`: 부하 실험의 외부 fallback/telemetry 상속을 차단하고 자원 표본을 기록한다.
  명시적 1만 key 실험은 setup 15분/전체 60분의 watchdog으로 제한한다.
  별도 clean backend `9dccfd0`에서 실제 10,000개 등록·20,000건 PASS 서명·30,004건 transaction
  검사를 끝냈으나 99,000요청 중 79,000회 완료 후 16번째 cell의 사후 assertion으로 실패했다.
  `48eddb3`의 `benchmarks/results/admission-matrix-10000-2026-09-09.json`은 PARTIAL_FAILED다.
  15개 cell 검증 통과·16번째 검증 실패·2개 미실행이며, 요청 완료 수를 ALLOW 성공 수로 읽지 않는다.
  원래 CLI가 stack과 cell 최종 집계를 보존하지 않아 `48 !== 0`의 정확한 invariant와 p95는 불명이다.
  시작/종료 결과 provenance 대신 실행 중/실패 후 일치한 진단 snapshot만 있으며 이를 명시했다.
  자원 표본 105개의 최대 RSS는 2,771,922,944 bytes다. 실패 원인 진단·부분 결과 보존을 고친 뒤
  작은 재현부터 검사하며, 이번 실패를 성공으로 바꾸거나 전체 실험을 자동 재시작하지 않는다.
  서명은 명시적 TEST_ONLY이고 공유 Windows 개발 PC의 Ganache 실험이지 독립 검증기관이나 운영 SLO가 아니다.
- `15d61b9` break-glass 통합: operator-signed 60초 이하 grant, 정확한 읽기 1회/identity/arguments/
  client metadata 고정, 원자적 ADMISSION→CALL 사용 기록, 암호화 audit, 원래 REVOKED 유지.
  Main 실제 stdio·별도 OS 프로세스 claim·준비 격리 계약 회귀 18개 통과. 공개 HTTP는 허용하지 않는다.
  사용 기록은 signed grant를 포함한 LOCAL_ENCRYPTED_UNANCHORED이며 외부 앵커 증거가 아니다.
  실제 prepared Docker emergency는 위 `54d3335` CI에서 통과했다.
  모든 RPC의 장애와 trust rejection 구분·부분 REVOKED/identity 오류를 timeout으로 덮지 않는 처리는
  `03318bb`에 통합됐고 새 Linux 검증은 대기다.
- 마스터 2.5.4.3의 외부 LLM 전체 source·환경변수 전송 금지와 기존 prepared full-source
  semantic 입력 사이의 충돌을 확인했다. 실제 외부 provider 호출은 아직 하지 않았다.
  외부 full-source를 기본 거부하고 합성 로컬 계약 테스트를 명시적으로 분리하는 수정은
  `b30d9fb`·`30d7751`에 통합했다.
  외부 AI에는 metadata·보안 관련 redacted diff/제한된 근거만 보내는 별도 coverage 계약과
  end-to-end 분석을 이어서 구현해야 하며, AI를 끄는 것으로 전체 요구사항을 완료 처리하지 않는다.

### 이전 체크포인트 이력 (해당 커밋 당시 상태)

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
  다시 실행했으며 최종 실패했다. Node 24 전체 회귀·빌드는 성공했다.
  PostgreSQL job `102190519546`는 성공: 동시 open, 업무 테이블 락 중 재연결,
  checksum 변조 거부, 준비 작업의 quota/원자성, 별도 DB backup/restore를 실제 검증했다.
  Node 22는 실제 builder 보안 검사, supplied-lock 오프라인 설치 및 두 페이지 MCP discovery를 통과했다.
  격리된 lock 생성 자체는 성공했지만 후속 설치가 `RUNTIME_INSTALL_EUSAGE`로 실패했고,
  full prepared scan은 `PREPARED_TRUST_ANCHOR_MISMATCH`로 INCONCLUSIVE였다. 원인 수정 및 Linux 재검증 필요.
  prepared 전체 흐름·OCI·Grafana 및 새 이미지 검증은 아직 통과 증거가 없고,
  10회 반복·signed-image 후속 job은 skipped다. 이전 이미지 성공을 최신 구현의 성공으로 대체하지 않는다.
  secret scan은 전체 파일을 검사하고 정확한 비밀키 유출 방지 assertion만 non-secret 예외로 추가했다.
- `8189363`: 기본 `/v1` 정책도 운영자 로컬 원본 catalog에서 새로 취득해 체인의 전체 identity와
  대조하고 독립 Docker 재스캔 후에만 서명하도록 연결했다. 원본·baseline·Docker가 없으면 서명하지 않는다.
  기존 공개 `/api` 데모 및 prepared 엄격 정책은 유지했다. 로컬 서명/원본 계약 9개 통과·Docker 1개 skip.
  이 변경은 위 `6e0ab7b` 실행에 포함되지 않으며 후속 Linux source-validator/fullcycle 검증이 필요하다.
  portable OTLP 회귀의 서명 span은 이제 명시적 TEST_ONLY_SIGNING이며 실제 production 독립 검증자
  실행을 증명하지 않는다. 실제 Docker 회귀는 production 서명 경로와 별도 root 연결 기록을 검사한다.
- `15319ab`: API와 Gateway가 plain Node 공통 V2 체인 조회기를 재사용한다. 전체 release identity,
  최신/확정 attestation 및 캐시 없는 블록 재확인을 유지하며 이동/재조직된 view는 허용하지 않는다.
  통합 타입 검사와 실제 로컬 EVM/원본·서명·전송 회귀 7개 통과, Docker 2개 명시 skip.
  standalone Gateway 이미지에 SDK와 prepared identity 검증의 누락된 import 파일을 추가했다.
- OCI native import·외부 MCP 관측 checkpoint를 통합하고 Linux 수용 검사를 추가했다.
  후보 바이너리는 Docker 내부에서만 실행하며, 원본/config/최종 filesystem/entrypoint digest를 바인딩한다.
  현 단계는 관측 전용으로 `ABSTAIN`, filesystem `NOT_OBSERVED`, binary `NOT_REVIEWED`이며
  OCI PASS·Gateway 실행·전체 100MiB 지원을 완료로 간주하지 않는다. 실제 Linux 결과는 아직 없다.
- `eb00dbf` 통합 로컬 전체 `npm test` 성공: backend 73 통과·외부 환경 6 skip,
  Security 82 통과·Docker 11 skip, Gateway 68 통과·Docker 1 skip, dashboard 23 통과,
  replay·MCP E2E·live smoke 성공. `f3c6214` 타입 검사와 Next production build 성공.
  OCI 자체 portable 검사 7 통과·Docker 1 skip이며, 테스트 개수는 완료율이나 탐지율이 아니다.
- `8dca40a`: npm 12의 extension hash 검사와 생성기의 확장 코드 미실행 정책을 일치시켰다.
  private install에서만 확장 파일을 분리하고 정확한 원문을 최종 closure에 복원한다.
  확장/patch 의존 lock은 실행하지 않고 명시 거부한다. Docker ADD 목적지 권한을 0555로 고정하고
  CLOSURE_PREPARED 반환 전 실제 final CID를 미실행 export해 원본 closure와 다시 대조한다.
  통합 관련 회귀 13 통과·Docker 4 skip. 원래 Linux 실패 2건의 실제 해소 여부는 후속 실행으로 확인한다.
- [Linux CI 34266169177](https://github.com/sihoon-0077/MCPShield/actions/runs/34266169177), `e2637c7`:
  Node 22/24 일반 회귀·빌드, PostgreSQL, trusted builder 보안 검사와 실제 npm closure 전체 단계 성공.
  앞선 generated-lock 설치 및 final closure/full scan 실패는 이 실행에서 해소됐다.
  이후 3건 실패: prepared Gateway fixture가 관측 host UID에도 1000을 강요했고,
  prepared fullcycle은 raw API 응답의 `status`를 Gateway 필드명 `releaseStatus`로 잘못 읽었다.
  OCI는 관측 전에 native load 단계에서 실패했다. 전체 실행은 실패이며 후속 배포/10회 반복은 skipped다.
- `44b229c`·`6cc80de`는 위 두 테스트 계약을 수정했다. non-root 관측 및 Gateway UID1000 경계를
  각각 유지하고, BLOCK/reasonCode/서명된 REVOKED도 검사한다. 폐기된 synthetic registry는 새 케이스에서
  재사용하지 않으며 terminal 기록을 지워 재허용하는 테스트 우회는 없다.
- `6363ce0`·`d1eda30`: OCI 로더 실패는 고정 코드만 반환하고, 검증된 원본 blob에 Docker-save
  표준 metadata를 추가해 native Docker가 직접 layer를 해석하도록 했다. 데몬/store 변경이나
  자체 layer 변환은 하지 않는다. 타입 검사와 관련 portable 11개 통과·Docker 2개 skip;
  실제 OCI load 및 두 prepared 회귀 수정의 Linux 수용 결과는 아직 대기다.
- clean `de4fc9f`의 실제 로컬 EVM·SQLite·HTTP 측정(40회/동시4/identity4):
  hot p95 83.500ms, uniform p95 60.727ms, signed REVOKED 40/40 BLOCK·캐시 재사용0회,
  해당 BLOCK p95 46.899ms, 다음 admission의 차단 확인 49.126ms.
  시작/종료 source hash는 `0585e0af2b31e72e6daee7f645f2c83a8432d346dff1e26e01094ac97cb3cc1f`로 동일하다.
  작은 Windows/Ganache 실험이며 운영 SLO·1만 key·실제 네트워크 장애 측정이 아니다.

- [Linux CI 34267533697](https://github.com/sihoon-0077/MCPShield/actions/runs/34267533697), `1ef0a47`:
  Node 22/24 일반 테스트·빌드 및 PostgreSQL backup/restore 성공. 실제 npm closure,
  prepared Gateway 격리·호출별 폐기, native OCI import·외부 non-Node MCP 관측도 성공했다.
  prepared fullcycle은 여전히 실패: 두 폐기 실행의 테스트 입력이 누락되어
  `PREPARED_MCP_INPUT_REQUIRED`에서 중단됐다. 전체 성공·10회 반복·새 signed image를 주장하지 않는다.
  이 실행의 OCI 성공은 작은 표본이며 아래 100MiB 추가 수용 검사를 포함하지 않는다.
- `54196f1`·`1bcd13a`: OCI source 100MiB, layer+final export 누적 512MiB,
  50,000 entries 및 1MiB JSON 상한을 고정하고 복사/해시를 bounded streaming으로 처리한다.
  인증·재시도·멈춘 응답 body 전체에 취득 deadline 120초를 공유한다.
  Linux 실제 100MiB MCP 실행 검사를 CI에 추가했으나 아직 실행 결과는 없다.
- `8f03f5d`: API 장애 시 서명 캐시→별도 신뢰키·자격증명의 조직 indexer→직접 RPC 경로를 통합했다.
  4xx·불량 서명·명시 BLOCK은 다음 경로로 우회하지 않는다. RPC는 읽기 전용·총 1.5초·고정 quota이며
  ALLOW를 캐시하지 않는다. 마지막 블록 30초 freshness 및 attestation 유효기간을 재검사한다.
  조직 서명/RPC의 폐기는 재시작·다른 tenant·정책에서도 유지한다. Main 직접 실행한 새 fallback·
  OCI portable 회귀 15개 통과·대용량 메모리 검사 1개 opt-in skip; 실제 로컬 EVM 정족수/폐기 포함.
- Backend clean `cb7bccf` 파일럿은 실제 64키·196트랜잭션·720회/18셀·동시16, 46.020초다.
  시작/종료 source hash `1152206630aa48d2e636615be3d5d33f611fe88b2c9cac1a2d912f6ed483c732` 일치.
  장애를 주입하지 않은 STATUS_UNAVAILABLE 87건과 관련 동시 요청 취소 34건을 별도로 기록했다.
  head가 움직일 때의 정상 요청 가용성을 개선 중이며, 이 측정은 `8f03f5d` freshness 추가 이전이다.
  10,000키 실행은 29.5분으로 외삽되어 20분 상한 내 실행하지 않았다. 외삽은 실측이 아니다.
  `76406de`·`1eeaccc`는 opt-in 10,000키/99,000요청 및 정확한 오류 분류 코드만 통합했다.

- `1eeaccc` 통합 후 Main 전체 `npm test` 및 `npm run build` 성공. Windows의 Docker/외부 DB 검사는
  명시 skip이며 위 Linux 증거와 구분한다. `801e504`는 prepared fullcycle 입력 누락을 수정했고
  portable guard 회귀 1개 통과·Docker 1개 skip이다. 실제 Linux 재실행 전에는 실패 해소로 확정하지 않는다.
  원본 `mcp/main`은 여전히 `6aa370285154f683989f2bf9b219bd2c052e6cee`다.
- `cdeebb7`: 온전한 VERIFIED view를 조회하는 동안 블록 높이만 상승하고 확정 블록 hash가
  유지된 경우에만, 원래 RPC deadline 안에서 전체 조회를 한 번 다시 수행한다.
  두 번째 view도 전체 identity·정책·확정성·시간·블록 hash를 검증한다. 재조직/폐기/반복 이동은
  오래된 ALLOW나 다른 provider 재시도로 회피하지 않는다. Main 새 Gateway/RPC 회귀 14개 통과,
  실제 V2 및 benchmark 분류 회귀 8개 통과·Docker 1개 skip, 타입 검사 성공.
- `f7bfc46`: prepared fullcycle의 Gateway-A/B는 서로 다른 OS 프로세스로 실행한다.
  private stdin으로 설정을 전달하고 각각의 signed REVOKED 응답을 검사한다.
  Docker lifecycle 관측은 정상 실행의 create/start를 positive control로 요구하고
  폐기 이미지 create/start 0건 및 남은 컨테이너 없음까지 검사한다. 256건 이상인 관측 창은
  누락 가능성 때문에 실패한다. portable 2개 통과·Docker 1개 skip; 실제 Linux 증거는 아직 없다.
- [Linux CI 34268881754](https://github.com/sihoon-0077/MCPShield/actions/runs/34268881754)는
  `db5469a` 통합본에서 PostgreSQL·Node 24·Node 22 일반 회귀/빌드 및 실제 runtime 검사가 성공했다.
  **100MiB OCI 실제 import/MCP 관측**, prepared worker+별도 검증자 4회 재스캔+V2 정족수,
  legacy 원본 독립 검증자 Docker 재실행 및 실제 scan→V2→Gateway가 통과했다.
  AI는 여전히 loopback 계약 stub이고 검증자는 같은 개발 기관이다. OCI는 관측 단계 ABSTAIN이다.
  전체 실행은 이후 Compose의 dashboard image 빌드에서 실패했다. BFF가 새로 import한 공유
  identity/binding/surface 모듈이 해당 Dockerfile COPY 목록에 없었다. `278b92c`·`14c6df3`·
  `7e18f0d`에서 root lock의 의존성, 실제 import 전체 파일과 타입 선언을 포함하고 기존 runtime의
  OpenSSL 보완을 유지했다. 실제 Docker 빌드 재검증이 필요하며 signed-image/10회 반복은 skipped다.
  위 `cdeebb7`·`f7bfc46`은 이 실행에 포함되지 않는다.
- 기존 Railway `/try`와 HTML 요청의 `/mcp`는 각각 HTTP 200을 확인했다.
  JSON/기본 Accept의 GET `/mcp`는 405이며 서버 코드의 MCP transport/HTML 분기와 일치한다.
  이는 기존 공개 경로의 HTTP 확인이며 새 master 배포나 MCP 도구 호출 성공 증거는 아니다.

명시적으로 남은 구현/검증은 범용 OCI 전체 검사·독립 서명·Gateway 연결, 새 fallback의 최신
전체 회귀 및 서명된 break-glass 감사, 전체 부하·평가 행렬이다. legacy 독립 재실행은 위
`db5469a`의 실제 Linux 회귀가 통과했으며, 이후 변경의 검증 범위는 커밋별로 구분한다.
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
| Blockchain·Backend | MCPShield-master-blockchain-backend / master/backend-benchmark | 내구성 작업·권한·정책 API, Trust Plane V2, 재처리·실측 |
| Frontend·Gateway | MCPShield-master-frontend-gateway / master/frontend-admission-fallback | 서명 캐시·폐기 전파·장애 대응·정책 집행, 운영 UI |

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
| FR-001–003 | npm/tarball/OCI 수집, 불변 버전, 출처 | Security / Backend | npm closure와 100MiB OCI native import/외부 MCP 관측은 이전 Linux 검증 통과. OCI inventory/Trivy/binding·정책·API worker·Gateway 연결 구현 및 portable 회귀 통과. OCI 독립 signer·실제 정상 PASS/악성 FAIL 전체 Linux 흐름과 최신 native 검증은 진행 중 |
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

1. 최신 전체 변경의 Linux/PostgreSQL 회귀 및 전체 exporter trace 실검증.
   `105f12f` Grafana/Prometheus 실제 지표 수집·npm prepared/독립 validator·PostgreSQL 성공과
   이후 HEAD 검증을 구분한다. synthetic metric pipeline은 전체 production trace 검증이 아니다.
2. OCI 전체 inventory/취약점/AI 검사·독립 서명·Gateway 실행 연결. 100MiB import/외부 관측 성공은
   전체 바이너리 안전성이나 무제한 source semantic coverage 증거가 아니다.
3. 고위험 receipt UI와 오래된 앵커 reorg 복구, 모든 운영 UI 세부 항목.
4. 실제 외부 LLM·Base Sepolia·비공개 S3/KMS/보존 정책·독립 validator 운영 검증.
5. hot/uniform·cache/RPC 장애 smoke 측정의 큰 표본 반복/운영 환경 검증, 다중 크기 scan 처리량,
   외부 라이선스 확인 데이터셋·독립 라벨·전체 ablation/실제 모델 agent ASR.
   기존 실제 Docker→EVM→두 Gateway 데모는 `229f147`에서 10회 연속 통과했으며,
   새 OCI 전체 흐름이나 외부 모델 검증의 대체 증거로 사용하지 않는다.
6. 공개 새 버전 배포, 최종 HEAD signed release 산출물·보안/라이선스 정책·배포/복원 증빙 점검.

이 목록은 작업 범위를 줄이는 제외 목록이 아니라 남은 작업/외부 검증 목록이다.
