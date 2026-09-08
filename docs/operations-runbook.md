# MCPShield 운영·복구 Runbook

현재 확장 구현 단계의 runbook이다. 명령 성공과 실제 외부 배포 완료를 구분한다.
최신 수용 결과는 `master-implementation-plan.md`를 함께 확인한다.

## 운영 콘솔 로컬 실행

기존 공개 데모를 건드리지 않는 포트 `3300/3301`을 사용한다.
먼저 `node scripts/ops/init-control.mjs`로 `.env.master.local`을 만든다.
매번 다른 admin/operator/reader 토큰, 증거 암호화 키, 서명 키를 만들며 값을 출력하지 않는다.
기존 파일은 덮어쓰지 않는다. Windows에서는 파일 ACL도 본인 계정으로 제한한다.

각 터미널에서 저장소 루트를 작업 디렉터리로 사용한다.

```sh
node --env-file=.env.master.local --import tsx apps/api/src/server.ts
node --env-file=.env.master.local --import tsx apps/api/src/control-worker-cli.ts
node --env-file=.env.master.local node_modules/next/dist/bin/next dev apps/dashboard --port 3300
```

`http://127.0.0.1:3300/console`에서 비공개 설정 파일의 해당 역할 토큰으로 로그인한다.
토큰을 채팅·스크린샷·Git에 올리지 않는다. API와 worker는 동일한 영속 control DB와
artifact/evidence 경로를 사용한다. 기본 스캔은 정적 전용으로 `INCONCLUSIVE`이며,
서명 키가 있다는 이유만으로 `VERIFIED`를 만들지 않는다.

Docker가 있는 Linux에서는 PostgreSQL과 worker를 분리한 실제 persistent stack을 실행할 수 있다.

```sh
docker compose --env-file .env.master.local -f docker-compose.yml -f compose.control.yml up --build --wait
```

DB 포트는 공개하지 않으며, worker/API에 Docker socket을 마운트하지 않는다.
Compose 콘솔 주소는 `http://127.0.0.1:3000/console`이다. 로컬 전용 HTTP 예외는
명시된 loopback origin에서만 적용한다. 공개 배포에는 `MCPSHIELD_PUBLIC_ORIGIN=https://...`
을 설정하고 loopback 예외를 끈다. 프록시 헤더를 보고 신뢰 origin을 추측하지 않는다.
이 구성의 worker도 정적 전용이다. 동적 검사는 별도 신뢰된 Linux worker 호스트에서
`CONTROL_SANDBOX_MODE=docker`와 동일 DB·비공개 artifact/evidence 저장소를 설정한다.
테스트넷과 외부 AI는 이 명령으로 생성되지 않는다.

## 준비된 npm 이미지의 비공개 전달

`/v1/releases/:sourceReleaseId/prepare`는 원본을 수정하지 않고 실행 환경이 포함된
별도 릴리스를 만든다. `DERIVED_RELEASE_CREATED`는 설치·식별 완료이며 승인이 아니다.
`/v1/releases/:derivedReleaseId/gateway-config`는 operator 전용 비공개 설정이다.
브라우저·로그에 서명 키를 넣지 않는다. 이 설정에는 도구 원문이 있을 수 있으므로 공개 첨부하지 않는다.

현재 실행 프로필은 Linux Docker의 **로컬 image config ID**를 고정한다. registry manifest digest와
다른 식별자이므로 `sha256:...`만 원격 registry 주소처럼 사용하지 않는다. 동일한 Docker daemon에서
worker와 Gateway를 실행하거나, 검증자·Gateway의 사설 호스트로 정확한 이미지를 전달한다.
표준 `docker image save/load`를 사용하며 별도 이미지 전송 프로토콜은 만들지 않는다.

아래 `<FINAL_IMAGE_CONFIG_ID>`는 신뢰된 operator 설정의 `binding.finalImageDigest`와 일치해야 한다.
먼저 충분한 디스크 여유를 확인하고 권한이 제한된 **새 파일 경로**를 사용한다. 기존 파일에 덮어쓰지 않는다.

```sh
docker image inspect <FINAL_IMAGE_CONFIG_ID> --format '{{.Id}} {{.Os}} {{.Architecture}}'
docker image save --output /private/new-release-runtime.tar <FINAL_IMAGE_CONFIG_ID>
sha256sum /private/new-release-runtime.tar
```

이미지 archive·checksum·Gateway 설정은 인증된 비공개 전달 수단으로 별도 검증자/Gateway 호스트에
전달한다. checksum은 전송 무결성 확인이며 보낸 사람의 신원이나 안전성 증명이 아니다.
후보 소스·의존성·라이선스가 포함되므로 CI 공개 artifact나 공개 registry로 자동 게시하지 않는다.

```sh
sha256sum /private/new-release-runtime.tar
docker image load --input /private/new-release-runtime.tar
docker image inspect <FINAL_IMAGE_CONFIG_ID> --format '{{.Id}} {{.Os}} {{.Architecture}}'
node apps/gateway/src/index.mjs stdio --prepared-identity /private/gateway.json
```

받는 쪽은 archive checksum과 고정 CID·OS·architecture를 독립 확인한다. `load` 자체는 후보를
실행하지 않는다. 검증자는 자신의 Docker에서 실제 파일을 읽어 closure·entrypoint를 다시 확인하며,
행동·AI의 독립성은 별도 재실행 서명 게이트가 필요하다. 단순히 API가 준 `PASS`를 서명하지 않는다.
Gateway는 정확한 release/binding/tool hash를 확인하고, 실행 전과 각 도구 호출 전 서명된 상태를 조회한다.
잘못된 CID·구성·서명·폐기 상태면 실행하지 않는다. 이미지가 없을 때 자동 pull하지 않는다.

실행 프로필은 network-none·read-only·nonroot·128MiB/0.5CPU다. 인터넷 메일/CRM 접속이나
임의 native addon/child process 지원을 의미하지 않는다. 그런 기능은 별도의 제한된 실행 정책,
증거·재검증·정확한 새 릴리스가 필요하다. 이미지 정리는 참조하는 릴리스와 실행 중 컨테이너를
확인한 후 operator가 개별 태그로 수행한다. 저장소 전체/전체 Docker 이미지 prune은 사용하지 않는다.

## 추적과 알림

기본값은 외부 telemetry 전송 없음이다. 추적 ID는 항상 생성·전파한다.
OTLP 수집기로 내보내려면 다음 서버 환경변수를 설정한다.

```text
MCPSHIELD_TELEMETRY_ENABLED=true
OTEL_SERVICE_NAME=mcpshield-api
OTEL_EXPORTER_OTLP_ENDPOINT=https://your-private-collector.example
```

로컬 개발용 수집기·Prometheus·Grafana는 아래 overlay로 실행한다.
원격 운영에는 사설 네트워크와 인증/TLS가 필요하다. 대시보드·수집기 포트를 공개하지 않는다.

```sh
node scripts/ops/init-control.mjs --observability --output .env.observability.local
docker compose --env-file .env.observability.local -f docker-compose.yml -f compose.observability.yml up --build --wait
```

Prometheus: `http://127.0.0.1:9090`. 알림은 Prometheus Alerts 화면에서 확인한다.
Grafana: `http://127.0.0.1:3100/d/mcpshield-operations`. 사용자 `operator`, 비밀번호는
비공개 `.env.observability.local` 파일의 값이다. 익명 접근·가입·사용량 통계 전송은 끈다.
이미 만든 설정은 덮어쓰지 않으며, control-plane 암호화 키와 별개로 생성한다.
컨테이너의 기존 Grafana 데이터 볼륨이 있으면 환경변수 변경으로 관리자 비밀번호가
자동 재설정되지는 않는다. UI의 비밀번호 변경 절차를 사용하고 볼륨을 삭제하지 않는다.
기본 dashboard는 실제 측정된 허용·차단, 지연, 단계 오류·처리시간과 수집기 상태를 표시한다.
없는 데이터는 `No data`이며 0이나 SLO 달성으로 채우지 않는다. 실행 원문은 포함하지 않는다.
CI의 `smoke-observability.mjs`는 실제 Grafana 13 API 프로비저닝·익명 거부와 공식 exporter→
collector→Prometheus 전달을 검증한다. 의도적으로 `MOCK` 지표만 생성한다. 공개 운영 배포 증거는 아니다.
구성 기준: [Grafana 파일 프로비저닝](https://grafana.com/docs/grafana/latest/administration/provisioning/),
[Grafana 13 dashboard API](https://grafana.com/docs/grafana/latest/developer-resources/api-reference/http-api/dashboard/).
현재 collector는 trace 요약을 stdout으로 내보내며 장기 trace 보존/조회 저장소가 아니다.
실제 알림 수신자를 연결하려면 운영 Alertmanager를 설정한다. 수신자가 없는 상태를
“사람에게 알림이 전달됨”으로 표현하지 않는다.

`traceparent`를 scan 작업에 보존하고 worker·validator·chain outbox·indexer에 전달한다.
최신 chain reportRoot와 동일 tenant/release/policy/COMPLETED scan만 찾아 `admission.decision`을 연결한다.
호출자의 별도 request latency span은 유지하며, 외부 caller trace/baggage를 scan의 부모로 가져오지 않는다.
추적 조회 실패가 허용·차단을 바꾸지는 않으며 추가 RPC를 만들지 않는다.
단계명·판정·상태만 metric label로 사용한다. 릴리스·스캔 식별자는 trace attribute다.
원문 도구 호출·메일·DB query·예외 메시지·환경변수는 자동 수집하지 않는다.

```sh
node --import tsx --test tests/integration/telemetry.test.ts
node --import tsx --test tests/integration/fullcycle-telemetry.test.ts
```

이 테스트는 실제 공식 OTLP exporter가 보낸 trace/metric을 로컬 수집 서버로 받아서
같은 trace ID의 부모·자식 관계와 비밀값/예외 내용 배제를 확인한다.

## 실행 허가 장애

1. Gateway 차단 사유, 요청의 trace ID, 최신 block·policy·유효기간을 확인한다.
2. RPC 실패와 악성 판정을 구분한다. 오류를 PASS로 바꾸지 않는다.
3. strict는 최신 상태를 얻지 못하면 차단한다. balanced는 서명·digest·정책·만료가
   모두 맞는 짧은 읽기 전용 캐시만 사용한다. 이미 관찰한 폐기는 장애 중에도 유지한다.
4. API/RPC가 복구되면 최신 상태로 재검사하고, 두 독립 Gateway의 차단 여부를 확인한다.
5. 잘못된 허용이 관찰되면 캐시를 임의 삭제해 재허용하지 말고 해당 Gateway 사용을 중단한다.

메모리 캐시는 동시 요청의 최신 차단·잘못된 응답 이후 도착한 과거 ALLOW를 폐기한다.
한 번 서명으로 확인한 `REVOKED`는 chain·registry·정확한 release에 대해 terminal이다.
이는 컨트랙트의 전역 `revoked[releaseId]`와 동일한 범위다. 정책·tenant·API 주소·토큰·operation·
validator-set을 바꿔 받은 과거/새 ALLOW도 이를 되돌리지 못한다.
메모리는 4,096개 terminal identity를 보존하며 포화 시 폐기를 지우지 않고 추가 허용을 차단한다.
재시작 후에도 보존하려면 wrapper별 파일 캐시를 사용한다. `.revoked` 비공개 sidecar에는 최초
서명된 폐기 증거를 별도로 저장하며 ALLOW의 짧은 TTL 이후에도 유지한다. 이 기록을 TTL cleanup이나
장애 복구라는 이유로 삭제하지 않는다. 다른 릴리스/정책 wrapper에는 새 파일 경로를 사용한다.
키 교체로 과거 증거를 확인할 수 없으면 자동 초기화하지 않고 차단한다. 서명 키 이력 확인은 operator 작업이다.
파일 캐시를 켠 경우 그 파일이 프로세스 간 기준이며, 같은 이름의 `.lock`을 배타적으로 연다.
캐시/폐기 저장 실패 시에도 lock을 남겨 다른 프로세스가 이전 허용을 재사용하지 못하게 한다.
이미 사용 중이면 기다리거나 잠금을 빼앗지 않고 차단한다. 캐시 파일은 wrapper마다 따로 지정한다.
비정상 종료 후 잠금이 남으면 모든 관련 wrapper가 중지됐는지 확인한 뒤 정확한 해당 잠금과
캐시의 복구를 운영자가 진행하고, 네트워크가 복구된 상태에서 새 서명 판정을 받아 재시작한다.
프로그램은 잠금 소유 프로세스가 죽었다고 추정해 자동 삭제하지 않는다.

## 검사 실패·DLQ

1. 운영 UI/API에서 scan ID, stage, attempt, last error code를 확인한다.
2. registry 일시 장애·worker 중단은 lease와 제한된 재시도를 통해 복구한다.
3. archive traversal, 무결성 오류, 잘못된 schema는 자동 재시도로 정상화할 문제가 아니다.
4. 입력/정책을 수정해야 하는 경우 새 요청과 이의제기 이력을 연결한다.
5. 기존 scan ID의 evidence/reportRoot를 덮어쓰지 않는다. retry 시 중복 체인 제출을 확인한다.

## 비공개 S3 증거 저장소

기본 저장소는 로컬 암호화 파일이다. 소유한 비공개 bucket을 준비한 경우에만
`CONTROL_S3_BUCKET`, `CONTROL_S3_REGION`을 설정한다. AWS SDK의 표준 서버 역할/IAM
또는 비공개 AWS 자격증명을 사용하며 브라우저에 전달하지 않는다. S3 호환 endpoint는
`CONTROL_S3_ENDPOINT=https://...`로 명시한다. 기본 SSE-S3 AES256이며,
KMS 사용 시 `CONTROL_S3_KMS_KEY_ID`를 추가한다. 애플리케이션의 tenant-bound AES-GCM도 유지한다.

bucket은 public access block·versioning·backup 정책을 운영자가 설정하고 검증해야 한다.
API/worker 역할에는 해당 evidence prefix의 GetObject/PutObject만 부여하고, DeleteObject와
bucket 관리 권한을 주지 않는다. 조건부 생성은 기존 bytes를 덮어쓰지 않으며, 충돌 시
기존 암호문을 다시 검증한다. 다운로드는 역할 검사 후 API를 통해서만 제공한다.
자동 삭제·보존 기간 변경·public presigned URL 발급은 하지 않는다.

`tests/integration/object-storage.test.ts`는 실제 AWS SDK의 서명된 HTTP 요청·SSE/조건부 생성
헤더·본문 크기와 시간 제한·tenant 암호화·변조를 확인한다. 로컬 계약 서버를 사용하므로
실제 cloud bucket의 ACL/내구성/복원 또는 KMS를 검증한 결과는 아니다.
원문에 제시된 MinIO Community 저장소는 2026년에 archive되었으므로 과거 이미지를
운영 기본값으로 자동 설치하지 않는다. S3 API 호환 경계를 유지한다.
근거: [조건부 생성](https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes.html),
[MinIO 공식 저장소](https://github.com/minio/minio).

## PostgreSQL 백업·복원

운영 플랫폼의 암호화 백업/PITR을 우선 사용한다. 접속 비밀번호를 CLI 인자·로그에 넣지 않는다.
`PGHOST`, `PGPORT`, `PGUSER`, `PGDATABASE`, `PGPASSFILE`을 비공개 실행 환경에 설정한다.

```sh
pg_dump --format=custom --file=mcpshield-backup.dump
pg_restore --list mcpshield-backup.dump
```

복원 drill은 **빈 별도 DB**에서 수행한다. 원 운영 DB를 대상으로 `--clean`을 실행하지 않는다.
복원 전 승인된 별도 `PGDATABASE`인지 확인하고 다음 명령을 실행한다.

```sh
pg_restore --exit-on-error --single-transaction --dbname="$PGDATABASE" mcpshield-backup.dump
```

암호화 evidence와 그 키는 DB와 별도로 백업한다. 키를 잃으면 DB 복원만으로 증거를 읽을 수 없다.
동일 tenant의 evidence GCM 인증 및 Merkle root를 재검증한다. RPO/RTO는 복원 시간을
측정한 후 보고한다. 코드와 migration만으로 5분 RPO·1시간 RTO를 달성했다고 주장하지 않는다.

## 체인 reorg·키 사고

canonical block hash와 indexer checkpoint를 비교하고 orphan projection을 rewind한다.
재구축 중 Gateway는 오래된 상태로 허용하지 않는다. tx receipt가 불명확할 때 새 nonce로
무작정 재전송하지 말고 operation/typed-data hash와 체인 이벤트로 확인한다.

검증자 키 유출 의심 시 해당 worker를 중단하고 거버넌스 절차로 validator set을 교체한다.
이전 set의 서명을 새 set에서 재사용하지 않는다. 영향 릴리스는 별도 재검증하고,
terminal REVOKED를 되돌리지 않는다. 실제 기관별 키 보관/HSM 복구는 별도 운영 증거가 필요하다.

## 배포·롤백

의존성 변경 후 `npm run lock:normalize`를 실행한다. Ganache의 bundled 개발용
shrinkwrap이 npm install 때 root lock에 끼워 넣은 `extraneous` 항목만 제거한다.
실제 의존성 버전이나 integrity는 바꾸지 않으며, Linux Node 22/24 CI로 재검증한다.

배포 전 unit/integration/실제 Docker 테스트, production dependency audit, secret scan을 수행한다.
공개 `/mcp`와 `/try`는 합성 데이터 데모를 유지한다. 운영 credential·evidence API를 익명 데모에 노출하지 않는다.

Railway Free의 현재 한도는 서비스당 0.5 GB RAM·1 vCPU이며, 무제한 무료 상시 운영을 뜻하지 않는다.
release-image smoke는 500,000,000 bytes·1 CPU·swap 없음에서 웹/MCP/9단계 Judge API와 종료를 검증한다.
이는 Docker에서 실제 통과한 커밋에 한해 짧은 데모 동작 증거이며 동시 사용자 부하·월간 비용·Railway 배포 성공 보증이 아니다.
격리 설치·스캔용 Docker daemon과 사설 DB/검증자 운영을 공개 데모 컨테이너에 몰아넣지 않는다.
근거: [Railway 요금제·리소스 한도](https://docs.railway.com/pricing/plans).

DB migration은 추가 방식으로 적용하고, 백업을 확인한 후 새 버전을 배포한다.
실패 시 이전 이미지로 롤백한다. 데이터 삭제나 기존 schema 재설계는 롤백 수단으로 쓰지 않는다.

## 재현 가능한 성능·장애 측정

```sh
node --import tsx scripts/ops/evaluate-admission.ts --requests 40 --concurrency 4 --identities 4
```

실제 로컬 Ganache EVM·SQLite WAL·loopback HTTP·Ed25519 검증의 hot/uniform 분포,
명시적 API/RPC 장애 주입, 읽기 전용 signed cache·만료·폐기 후 재허용 거부,
실제 거래의 gas 및 receipt 후 다음 확인까지 차단 시간을 측정한다.
매 실행은 새 임시 DB/로컬 체인에서 시작하며 외부 체인·운영 DB·지갑을 사용하지 않는다.
스캔 보고서는 합성 입력이므로 탐지율, 독립 기관 합의, 테스트넷 성능을 측정하는 명령이 아니다.
샘플 수·동시성·플랫폼·source commit·dirty 여부가 JSON에 포함된다. 작은 smoke 표본의 p99를
운영 SLO로 인용하지 않는다. Windows Ganache가 native μWS 대신 JS fallback을 쓰는 경고도
측정 환경의 한계다. close-listener 경고는 해당 fallback 경로에서 관찰되며 숨기지 않는다.

### 서명 이미지·SBOM 검증

`MCPShield Verification`을 `master/main`에서 수동 실행하면 모든 테스트 통과 뒤
`signed-image` job이 실제 Docker 이미지를 빌드하고 Trivy 취약점·라이선스 목록과
CycloneDX SBOM을 만든다. HIGH/CRITICAL 스캔 실패를 성공으로 바꾸지 않는다.
GitHub OIDC 기반 provenance·SBOM 서명을 만든 뒤 같은 저장소 신원으로 검증한다.
생성된 이미지 archive와 보고서는 CI artifact로 1일만 보관하며 public registry에는 push하지 않는다.
실행 전에는 구성 완료일 뿐, 서명 이미지가 생성·검증됐다는 증거가 아니다.

다운로드 후 압축을 풀고 다음처럼 확인한다.

```sh
gh attestation verify mcpshield-image.tar.gz --repo sihoon-0077/MCPShield
docker load --input mcpshield-image.tar.gz
```

라이선스 목록 수집은 법률 검토나 프로젝트의 공개 라이선스 선택을 대신하지 않는다.
기준: [GitHub artifact attestation](https://github.com/actions/attest),
[Trivy image scan](https://trivy.dev/docs/latest/target/container_image/).

공식 구성 참고: [OpenTelemetry Node](https://opentelemetry.io/docs/languages/js/getting-started/nodejs/),
[Collector](https://opentelemetry.io/docs/collector/configuration/),
[Prometheus alerting](https://prometheus.io/docs/prometheus/latest/configuration/alerting_rules/).
