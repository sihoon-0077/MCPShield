# ADR-004: 블록체인이 필요한 장면 — 운영사가 장악되거나 멈췄을 때

- Status: Accepted
- Scope: 캡스톤 최종 데모 장면과 "왜 블록체인인가" 설명
- Date: 2026-10-11
- Related: 1차 멘토링(2026-10) M5, M9, M10, M13, M19

## Decision

"체인이 없으면 깨지는 장면"을 하나로 고정한다.

> **판정에 서명해 주는 운영사의 서명 키가 장악되면, 체인을 직접(자기 API로) 읽는 회사만 폐기된 버전을 계속 막는다. 운영사가 멈추면, 그 회사만 정상 버전을 계속 쓴다(운영사만 믿는 회사는 모든 호출을 막고 멈춘다).**

Gateway는 2개다.

| | Gateway A (회사 A) | Gateway B (회사 B) |
|---|---|---|
| 판정 조회 | 운영사가 호스팅하는 Control API | 회사 B가 직접 띄운 Control API (자체 DB·자체 Ed25519 서명키) |
| 믿는 대상 | 운영사 서명키 | 회사 B 서명키만 고정(pin). 운영사에 접속하지 않는다 |
| 체인 확인 | 운영사 API가 대신 읽는다. Gateway A는 다시 확인하지 않는다 | 회사 B API가 체인을 직접 읽는다 |
| 역할 | 편의 모드이자 **대조군** | 체인을 제대로 쓰는 모드 |

장면 순서 (테스트 하네스의 장면 번호와 같다):

1. 정상 v1.0.0이 2-of-3 PASS로 VERIFIED → A·B Gateway 자식 프로세스의 `inspect`(판정만 하고 실행하지 않음) 결과가 모두 ALLOW. 실제 MCP stdio `tools/call`(`list_messages`)이 Gateway A 경유, Gateway B 경유, 직접 연결 모두 성공.
2. **운영사 장애:** 운영사 엔드포인트가 멈춘다(소켓을 끊는 로컬 스위치). A의 실행 중 세션은 다음 호출을 거부하고(`Admission unavailable; strict or non-read-only calls fail closed`) 그 세션을 끝낸다(fail closed, 업무 정지). B의 세션은 계속 동작한다. 읽기/쓰기 처리표는 [ADR-006](adr-006-gateway-recheck-policy.md).
3. 악성 v1.0.1이 격리 → 검증자 2명 FAIL → 체인에 REVOKED → A·B Gateway를 `run` 하위 명령(허용되면 후보를 실제로 실행하는 명령)으로 띄우면 둘 다 종료 코드 3과 REVOKED 차단 판정으로 끝난다. 코드상 이 종료는 후보를 spawn하기 전에만 나므로, 폐기 사례에 대한 Gateway CLI 수준의 실행 전 거부 증거다(로컬 EVM, CAP2-302의 폐기 사례). (후보 실행 횟수를 직접 세지는 않는다. 종료 코드 3과 stderr의 차단 판정이 spawn 이전 경로에서만 나온다는 코드 근거에 기댄 간접 증거이며, [v2.1 §10.1](MCPShield_캡스톤_최종_마스터문서_v2.1.md)의 "후보 entrypoint 실행 0건" 직접 증거(실행 표식·프로세스 기록)는 이 하네스가 남기지 않으므로 별도로 확보한다.) 이 장면의 Gateway A `run`은 폐기 기록 파일(`MCPSHIELD_ADMISSION_CACHE_FILE`)을 켜고 실행하며, 장면 4의 "기록이 있는 A"가 같은 파일을 쓴다. 장면 4의 "처음 보는 A"와 장면 5 세션은 이 파일 없이 실행한다.
4. **운영사 서명 키 장악:** 공격자가 운영사의 admission 서명 키·키 ID·테넌트 토큰을 쥐고, 폐기된 v1.0.1을 VERIFIED로 보여 주는 조작된 체인 뷰로 ALLOW를 서명한다. 체인의 실제 상태는 여전히 REVOKED다. 결과는 세 가지이며 모두 테스트가 단언한다.
   - Gateway A, 처음 보는 경우(새 프로세스, 폐기 기록 없음, 폐기를 직접 본 적 없음): ALLOW. 속는다(대조군).
   - Gateway A, 장면 3의 폐기 기록이 있는 경우: BLOCK(`Release was previously revoked...`). 로컬 기록은 **A가 이미 본 폐기만** 지킨다.
   - Gateway B(회사 B 자체 API가 체인을 읽음): BLOCK, REVOKED.

   즉 운영사만 믿는 Gateway는 **자기가 직접 보지 못한 폐기**(운영사가 장악된 동안 일어난 폐기, 새로 설치한 Gateway 등)에 대해 속고, Gateway B는 그렇지 않다. 하네스가 재현하는 것은 이 **서명 키 장악**이며, API 프로세스 전체 장악은 아래 Consequences에 따로 적는다.
5. (측정용) 검증자 C가 운영사를 거치지 않고 체인에 긴급 격리를 직접 보낸다 → A·B의 이미 열린 세션이 다음 호출을 `RELEASE_QUARANTINED (QUARANTINED)` 이유로 거부하기까지의 시간을 잰다([ADR-006](adr-006-gateway-recheck-policy.md)). 2-of-3 FAIL 폐기의 실행 중 세션 전파는 재지 않는다.

## Reason

### 왜 "운영사 DB 조작"은 장면이 아닌가

처음에는 "운영사 DB에서 REVOKED를 VERIFIED로 고치는" 장면을 생각했다. 코드를 확인하니 **이 장면은 성립하지 않는다.** 운영사 API는 판정 요청마다 체인을 다시 읽고, DB가 아니라 체인 상태로 서명한다. DB를 어떻게 바꿔도 결과는 REVOKED·DIGEST_MISMATCH·POLICY_MISMATCH·STATUS_UNAVAILABLE 중 하나이고 모두 차단이다.

즉 **DB 변조만으로는 거짓 허용을 만들 수 없다.** 이것 자체가 설계의 장점이다. 그래서 현실적인 위협은 "DB"가 아니라 "운영사의 서명 권한 장악"으로 잡는다.

### 블록체인이 실제로 더해 주는 것

"중앙 DB는 판정을 숨길 수 있다"만으로는 약하다. 투명성 로그(예: Sigstore Rekor)도 조용한 삭제는 막는다. 세 방식을 나란히 비교한다.

| 위협 | 중앙 DB (운영사 1곳) | 단일 운영자 + 투명성 로그 (+ 클라이언트 검증) | 블록체인 (컨소시엄 검증자 + 컨트랙트, 체인을 직접/자기 API로 읽는 회사 기준) |
|---|---|---|---|
| 조용한 삭제·수정 | 못 막음 | 막음. 추가만 되는 로그와 포함 증명 | 막음. 블록에 남고 REVOKED는 되돌릴 수 없음 |
| 회사마다 다른 답 (split-view) | 못 막음 | 부분. 증인(witness)·가십을 갖추면 **사후 탐지**. 그 사이에는 속을 수 있음 | 막음. 모두 같은 상태를 읽음 (각자 노드 또는 복수 RPC 전제) |
| 규칙 집행 (2-of-3, 폐기 불가역, 중복 투표 거부) | 운영사 코드를 믿어야 함 | 부분. 로그는 기록만 함. 각 회사가 검증자 서명·규칙을 직접 확인하면 가능하나 회사마다 따로 구현 | 막음. 컨트랙트가 쓰기 시점에 거부 |
| 운영사 장애 | 전원 정지 | 부분. 미러·캐시로 완화, 새 판정 공급은 운영자에 의존 | 막음. 각 회사가 체인을 직접 읽음 |
| 운영사 서명키 탈취 | 거짓 허용이 통과 | 부분. 거짓 기록이 로그에 남아 사후 적발. 클라이언트가 검증자 서명을 직접 확인하면 차단 가능 | 체인을 읽는 회사(B)는 차단. **운영사 서명만 믿는 회사(A)는 직접 보지 못한 폐기에 대해 여전히 속음** |

정직한 결론: **투명성 로그와 클라이언트 측 검증을 제대로 갖추면 상당 부분을 대신할 수 있다.** 그래도 블록체인을 택한 이유는 다음과 같다.

- **규칙을 한 곳에서 집행한다.** 정족수, 폐기 불가역, 중복 투표·서명 재사용 거부를 컨트랙트가 쓰기 시점에 거부한다. 로그 방식이면 이 규칙을 회사마다 Gateway에 따로 구현하고 서로 맞춰야 한다.
- **회사마다 다른 답을 "사후 탐지"가 아니라 구조로 막는다.** 모든 회사가 같은 상태를 읽는다.
- **운영자 없이 읽는다.** 운영사가 멈춰도 각 회사가 체인을 직접 읽는다.
- 대가: 가스 비용, 확정 지연, 체인·RPC 의존.

마지막 행이 중요하다. 블록체인을 써도 **Gateway A처럼 운영사 서명만 믿으면 보호받지 못한다.** A의 로컬 폐기 기록은 A가 이미 본 폐기만 막고, 장악 중에 일어난 폐기나 새로 설치한 Gateway는 막지 못한다. 체인의 이점은 체인을 직접(또는 자기 API로) 읽는 회사만 얻는다. 그래서 두 Gateway를 나란히 보여 준다.

## Alternatives considered

- **운영사 DB 변조 장면:** 위 이유로 코드상 성립하지 않는다.
- **운영사 API의 RPC를 거짓 노드로 바꾸는 장면:** 체인 조회기가 최신·확정 블록 양쪽의 판정, 신원 재계산, 검증자 버전, head 신선도, 블록 해시를 교차 확인한다. 일관된 거짓 응답을 모두 만들어야 해서 연출과 설명이 복잡하다. 채택하지 않는다.
- **Gateway 하나만 체인을 읽게 해서 보여 주기:** 대조군이 없으면 "체인이 없으면 무엇이 깨지는지"가 보이지 않는다.
- **투명성 로그만 사용:** 정당한 대안이다. 위 표로 차이를 공개하고, 정식 비교는 후속 과제로 남긴다.

## Consequences

- 데모 메시지: "운영사를 믿는 회사(A)는 운영사가 멈추면 함께 멈추고, 운영사 서명 키가 장악되면 자기가 직접 보지 못한 폐기에 대해 속는다. 체인을 직접 읽는 회사(B)는 버틴다."
- **운영사 API 프로세스 전체가 장악되는 경우(MVP의 한계):** MVP에서는 릴리스 등록·정책 게시가 owner 전용이라 운영사 relayer 키가 곧 세 레지스트리의 owner 키다([`contracts/scripts/deploy-v2.ts:20-23`](../contracts/scripts/deploy-v2.ts#L20-L23), [`apps/api/src/chain-outbox.ts:52-54`](../apps/api/src/chain-outbox.ts#L52-L54)). 그래서 API 프로세스 전체가 장악되면 공격자는 서명 키뿐 아니라 owner 권한도 갖는다. 이때도 REVOKED→VERIFIED는 불가능하고 B는 REVOKED를 계속 차단한다(거짓 ALLOW 없음). 그러나 `disable`·`deprecate`로 정상 릴리스까지 EXPIRED로 만들 수 있고, B가 고정한 검증자 집합 버전도 맞지 않게 되어 A·B 모두 실패-닫힘으로 멈출 수 있다(서비스 거부). 운영에서는 owner(멀티시그)와 relayer 키를 분리한다([ADR-007](adr-007-registry-owner-governance.md)).
- 회사 B는 자체 Control API·DB·서명키를 운영해야 한다(운영 비용). Gateway A 모드는 편의를 위해 남기되, 위험을 문서에 표시한다.
- 이번 변경에서 이 장면은 **LOCAL_EVM(Ganache) 자동 통합 테스트**로 구현된다. Base Sepolia 공개 실증과 docker-compose·대시보드 화면 연출은 아직 아니다([ADR-005](adr-005-capstone-demo-path.md)).
- 한계: 두 회사가 같은 로컬 RPC를 쓴다(운영에서는 각자 노드 또는 복수 제공자). 스캐너는 REPORT FIXTURE 대역(test double)이다. 검증자 3개는 팀이 운영하는 테스트 키이며 운영사 템플릿에 독립 재검사 없이 서명한다([ADR-003](adr-003-validator-consortium.md)). 결과 JSON은 이를 `environment`의 `chain: LOCAL_EVM_GANACHE`, `scanner: REPORT_FIXTURE_TEST_DOUBLE`, `validators: SINGLE_INSTITUTION_DEMO`, `governance`(배포 결과 값), `validatorVerification: SIGNS_OPERATOR_TEMPLATE_NO_INDEPENDENT_RESCAN`, `rpc: ONE_SHARED_LOCAL_RPC_FOR_BOTH_COMPANIES`와 `limitations` 배열로 표시한다.
- 참고: 픽스처 v1.0.1은 Gateway의 로컬 실행 정책(`node:http` import 금지)에도 걸린다. A가 거짓 허용을 받은 뒤에도 실행 자체는 이 별도 방어층에서 거부될 수 있다. 장면 4는 `inspect`로만 확인하므로, 이 장면이 증명하는 것은 **판정 단계에서 (폐기를 본 적 없는) A가 거짓 허용을 받았다**는 사실이다.

## Evidence / verification

- 운영사 API는 요청마다 체인 판정을 읽고 체인 상태로 서명: [`apps/api/src/control-plane.ts:288-296`](../apps/api/src/control-plane.ts#L288-L296), [`:309-319`](../apps/api/src/control-plane.ts#L309-L319)
- DB에 UNVERIFIED가 있어도 체인 조회가 VERIFIED면 서명 ALLOW (API는 체인만 믿음): [`tests/api/control-plane.test.ts:25, 38-39, 65-66`](../tests/api/control-plane.test.ts#L25-L66)
- Gateway는 서명과 고정 문맥만 검증하고 체인을 다시 확인하지 않음: [`apps/gateway/src/signed-admission.mjs:82-101`](../apps/gateway/src/signed-admission.mjs#L82-L101)
- 체인 조회기의 교차 확인: [`packages/contracts-sdk/src/v2-chain-reader.mjs:62-110`](../packages/contracts-sdk/src/v2-chain-reader.mjs#L62-L110)
- 실행 정책의 `node:http` 금지: [`packages/artifact-policy/import-policy.mjs:11-14`](../packages/artifact-policy/import-policy.mjs#L11-L14)
- 장면 테스트(장면 2: 운영사 장애, 장면 4: 운영사 admission 서명 키 장악, 하네스의 `lyingView`): [`tests/integration/consortium-scene.ts`](../tests/integration/consortium-scene.ts), [`tests/integration/consortium-scene.test.ts`](../tests/integration/consortium-scene.test.ts)
- 장면 1·4의 Gateway 판정은 `inspect` 하위 명령(실행하지 않고 판정만 함, 결과 `method: GATEWAY_CHILD_PROCESS_INSPECT_NEVER_SPAWNS`)으로 확인한다: 하네스의 `inspectInChild`([`consortium-scene.ts`](../tests/integration/consortium-scene.ts)), [`apps/gateway/src/index.mjs:230-239`](../apps/gateway/src/index.mjs#L230-L239)
- 장면 3은 `run` 하위 명령으로 확인한다. 종료 코드 3 + `AdmissionBlockedError` 판정이면 `refusedBeforeSpawn: true`: 하네스의 `runInChild`, [`apps/gateway/src/index.mjs:510-515`](../apps/gateway/src/index.mjs#L510-L515)(차단은 spawn 전 `admittedSnapshot`에서 발생, [`:287-290`](../apps/gateway/src/index.mjs#L287-L290))
- 로컬 폐기 기록(`.revoked`)과 "previously revoked" 거부: [`apps/gateway/src/signed-admission.mjs:142-155`](../apps/gateway/src/signed-admission.mjs#L142-L155), [`:243-246`](../apps/gateway/src/signed-admission.mjs#L243-L246)
- 장면 불변 조건은 하네스의 `assertConsortiumReport` 한 곳에 있고, 테스트와 평가 스크립트가 같은 함수를 쓴다. 장면 4 결과는 `scenes.operatorCompromised.{gatewayAFirstSight, gatewayAWithJournal, gatewayB}`에 남는다.
- 측정 결과(운영사 장애 시 A·B 동작, 지연): `npm run evaluate:consortium-scene` → `benchmarks/results/consortium-scene-<sha7>-<timestamp>.json`(`--allow-dirty`로 실행하면 이름에 `-dirty-<소스 해시 8자리>`가 붙는다). 수치는 공식 측정(커밋 `f85f8e8`, Windows 개발 PC·Node v24.13.0, 표본 50) [결과 JSON](../benchmarks/results/consortium-scene-f85f8e8-2026-10-10T18-00-42-747Z.json) ([ADR-006](adr-006-gateway-recheck-policy.md) 측정표)
