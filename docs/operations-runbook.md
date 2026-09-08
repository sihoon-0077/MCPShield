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

## 추적과 알림

기본값은 외부 telemetry 전송 없음이다. 추적 ID는 항상 생성·전파한다.
OTLP 수집기로 내보내려면 다음 서버 환경변수를 설정한다.

```text
MCPSHIELD_TELEMETRY_ENABLED=true
OTEL_SERVICE_NAME=mcpshield-api
OTEL_EXPORTER_OTLP_ENDPOINT=https://your-private-collector.example
```

로컬 개발용 수집기와 Prometheus는 아래 overlay로 실행한다.
원격 운영에는 사설 네트워크와 인증/TLS가 필요하다. 대시보드·수집기 포트를 공개하지 않는다.

```sh
docker compose -f docker-compose.yml -f compose.observability.yml up --build --wait
```

Prometheus: `http://127.0.0.1:9090`. 알림은 Prometheus Alerts 화면에서 확인한다.
현재 collector는 trace 요약을 stdout으로 내보내며 장기 trace 보존/조회 저장소가 아니다.
실제 알림 수신자를 연결하려면 운영 Alertmanager를 설정한다. 수신자가 없는 상태를
“사람에게 알림이 전달됨”으로 표현하지 않는다.

`traceparent`를 scan 작업에 보존하고 worker→validator→chain/admission으로 전달한다.
단계명·판정·상태만 metric label로 사용한다. 릴리스·스캔 식별자는 trace attribute다.
원문 도구 호출·메일·DB query·예외 메시지·환경변수는 자동 수집하지 않는다.

```sh
node --import tsx --test tests/integration/telemetry.test.ts
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

## 검사 실패·DLQ

1. 운영 UI/API에서 scan ID, stage, attempt, last error code를 확인한다.
2. registry 일시 장애·worker 중단은 lease와 제한된 재시도를 통해 복구한다.
3. archive traversal, 무결성 오류, 잘못된 schema는 자동 재시도로 정상화할 문제가 아니다.
4. 입력/정책을 수정해야 하는 경우 새 요청과 이의제기 이력을 연결한다.
5. 기존 scan ID의 evidence/reportRoot를 덮어쓰지 않는다. retry 시 중복 체인 제출을 확인한다.

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
DB migration은 추가 방식으로 적용하고, 백업을 확인한 후 새 버전을 배포한다.
실패 시 이전 이미지로 롤백한다. 데이터 삭제나 기존 schema 재설계는 롤백 수단으로 쓰지 않는다.

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
