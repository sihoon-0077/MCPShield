# ADR-005: 캡스톤 최종 데모 경로는 하나 — V2 + 서명 판정 + 회사별 조회

- Status: Accepted
- Scope: 캡스톤 최종 데모·발표·심사에서 "진짜 경로"로 보여 줄 실행 경로
- Date: 2026-10-11
- Related: 1차 멘토링(2026-10) M1, M10, M11, M14, M16, M19

## Decision

최종 데모 경로를 하나로 고정한다.

| 항목 | 최종 데모 경로 |
|---|---|
| 브랜치 | `master/main` (2026-10-11부터 GitHub 기본 브랜치) |
| 컨트랙트 | `ReleaseRegistryV2` (+ `ValidatorRegistry`, `PolicyRegistry`)만 사용 |
| Gateway 판정 방식 | 서명된 `/v1/admission/check` (Gateway 서명 모드, strict) |
| Gateway A 조회 경로 | 운영사 Control API → 운영사 공개키로 서명 검증 |
| Gateway B 조회 경로 | 회사 B Control API(체인 직접 조회) → 회사 B 공개키만 고정 |
| 체인 | 자동 회귀·장면 테스트는 LOCAL_EVM(Ganache). 공개 실증은 Base Sepolia (**미완료**) |
| 스캐너 | 장면 하네스는 REPORT FIXTURE 대역(test double). 실제 Docker 검사는 별도 경로 |

나머지는 지우지 않고 **"확장(extension)"** 이름표를 붙여 최종 데모 경로에서 뺀다.

| 확장 항목 | 처리 |
|---|---|
| V1 `ReleaseRegistry` + 무서명 레거시 `/api` 판정 | 현재 compose 기본값. 레거시로 보존 |
| break-glass 긴급 실행 | 로컬 stdio 전용 기능으로 보존. 데모 경로에서 제외 |
| action receipt 온체인 앵커링 | 코드·검증 자료 보존 |
| 제한형 OCI | 기존 프로필·테스트만 유지 |
| Streamable HTTP 원격 데모(`/mcp`, `/try`) | 합성 데모로 보존 |
| PostgreSQL 전환 | 진행 중 작업 보존. 본선 장면의 판정 근거 아님(판정은 체인에서 읽음) |
| balanced 서명 캐시 | 장애 시 읽기 전용만 허용. [ADR-006](adr-006-gateway-recheck-policy.md) |
| Gateway의 조직 indexer·직접 RPC 폴백 | 판정 API 장애 시 보조 경로. 기본 꺼짐 |

## Reason

- 여러 경로가 함께 있으면 심사자가 어느 것이 "진짜 데모"인지 알 수 없다. 하나를 고정하고 나머지에 이름표를 붙인다.
- 검증자 교체·판정 만료·긴급 격리는 V2에만 있다. 최종 주장(폐기 → 두 Gateway 차단)은 V2 기능 위에 서 있다.
- 무서명 레거시 경로에서는 Gateway가 응답을 그대로 믿는다. 서명 모드여야 Gateway마다 "누구의 판정을 믿는지"를 따로 고정할 수 있고, 그래야 [ADR-004](adr-004-blockchain-necessity-scene.md)의 장면이 성립한다.
- 심사자가 오래된 기본 브랜치(9월 5일 상태)를 보던 문제는 해결했다. 이제 `master/main`이 기본이다.

## Alternatives considered

- **V1을 최종으로:** 단순하지만 교체·만료·격리가 없어 거버넌스와 재검사 질문에 답할 수 없다.
- **V1과 V2를 모두 시연:** 범위가 흐려진다. 1차 멘토링에서 지적된 문제 그대로다.
- **compose 화면부터 V2로 전환:** 작업이 크고(배포 래퍼, V2 seed, probe·대시보드 수정), 장면이 맞는지를 먼저 증명하지 못한다. 그래서 이번에는 자동 테스트로 장면을 먼저 고정하고, compose 전환은 다음 단계로 둔다.

## Consequences

현재 차이 (정직하게 공개):

- `docker-compose.yml`은 아직 **V1을 배포**하고, 두 Gateway가 **같은 운영 API를 무서명 레거시 모드**로 쓴다(`MCPSHIELD_POLICY_HASH` 미설정). 즉 지금 compose 화면은 이 ADR의 최종 경로가 아니다.
- 대시보드 live 화면은 레거시 ID `mail-mcp@1.0.1`의 BLOCK/REVOKED 증거만 받는다. "A는 허용, B는 차단" 장면을 화면에 넣으려면 수정이 필요하다.

이번 변경이 한 것:

- 최종 경로를 LOCAL_EVM 자동 통합 테스트로 구현했다(`9c7bc9d`). 장면이 지켜야 할 조건은 하네스의 `assertConsortiumReport` 한 곳에 있으며, 테스트는 이 함수를 표본 5로 호출한다. 이 테스트는 `npm run test:backend`(CI의 `npm test`)에 포함된다. 아직 CI 실행 결과는 없으며 PR 후 확인한다.
- 같은 하네스와 같은 조건 함수로 더 많은 표본(기본 50)을 재는 평가 스크립트(`npm run evaluate:consortium-scene`)를 추가했다. 작업 트리가 깨끗하지 않으면 결과를 쓰지 않고(`--allow-dirty`로 실행하면 그 사실을 결과에 기록), 조건이 하나라도 깨지면 결과를 쓰지 않으며, 기존 결과 파일을 덮어쓰지 않는다(`benchmarks/results/consortium-scene-<sha7>-<timestamp>.json`. `--allow-dirty`로 실행하면 이름에 `-dirty-<소스 해시 8자리>`가 붙는다). 측정 대상 코드를 불러오기 전에 주변의 `MCPSHIELD_*`·`OTEL_*` 환경변수를 지우고 telemetry를 끈다. 결과 수치는 ⟦측정값⟧.

다음 단계 (이번 변경 아님):

1. compose를 V2 두 회사 스택으로 전환: V2 배포 주소를 env로 남기는 래퍼, V2 seed(정책 publish → 릴리스 등록 → 검사 → 검증자 서명), 운영사·회사 B API의 `CONTROL_V2_*` 설정, 두 Gateway 서명 모드 설정, gateway probe·`compose.test.ts`·대시보드·백엔드 헬스체크(V1 `ledgerMode` 요구) 수정.
2. Base Sepolia 공개 실증.
3. 실제 AI 연동과 실제 Docker 검사를 이 경로에 연결.

문서·다이어그램도 이 경로 기준으로 다시 그린다. 검증 흐름(릴리스당 1번, 실행 경로 밖)과 실행 흐름(매 도구 호출, 사용자가 기다리는 중)을 분리하고, Gateway별 판정 조회 경로를 표시한다.

## Evidence / verification

- Gateway 서명 모드 진입 조건 `MCPSHIELD_POLICY_HASH`: [`apps/gateway/src/index.mjs:83`](../apps/gateway/src/index.mjs#L83)
- 서명 판정에 필요한 고정 설정(키·체인·컨트랙트·검증자 버전·테넌트): [`apps/gateway/src/signed-admission.mjs:109-133`](../apps/gateway/src/signed-admission.mjs#L109-L133)
- V2 배포 스크립트(업그레이드 불가): [`contracts/scripts/deploy-v2.ts:6-26`](../contracts/scripts/deploy-v2.ts#L6-L26)
- compose 현황 — Gateway 공통 API 주소 [`docker-compose.yml:25-37`](../docker-compose.yml#L25-L37), V1 배포 [`:79`](../docker-compose.yml#L79), V1 헬스체크 [`:115`](../docker-compose.yml#L115)
- 대시보드 live 증거 조건: [`apps/dashboard/app/api/live/route.ts:21-23`](../apps/dashboard/app/api/live/route.ts#L21-L23)
- break-glass 원격 경로 차단: [`apps/gateway/src/index.mjs:400`](../apps/gateway/src/index.mjs#L400)
- 최종 경로 테스트: [`tests/integration/consortium-scene.test.ts`](../tests/integration/consortium-scene.test.ts), 평가: [`scripts/ops/evaluate-consortium-scene.ts`](../scripts/ops/evaluate-consortium-scene.ts)
