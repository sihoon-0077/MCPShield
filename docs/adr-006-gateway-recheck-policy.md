# ADR-006: Gateway는 매 도구 호출마다 판정을 다시 확인한다

- Status: Accepted — reuse window pending measurement
- Scope: Gateway 실행 경로(매 `tools/call`)의 재확인 정책과 판정 서버 장애 시 동작
- Date: 2026-10-11
- Related: 1차 멘토링(2026-10) M1, M2, M3, M19

## Decision

1. 기본은 **strict**다. Gateway는 `tools/call`마다 서명된 판정을 새로 받는다. 지난 판정을 재사용하지 않는다.
2. **재사용 창(N초 동안 판정 재사용)은 측정 결과로만 정한다.** 지금은 0초다. 재사용 창은 곧 "폐기된 릴리스가 계속 실행될 수 있는 최대 시간"이므로, 도입하면 그 값을 반드시 함께 보고한다.
3. 판정 서버가 멈췄을 때(조직 indexer·직접 RPC 폴백을 켜지 않은 본선 구성 기준):

| 모드 | 읽기 전용 호출 | 쓰기 호출 |
|---|---|---|
| strict (기본) | 차단 (fail closed) | 차단 (fail closed) |
| balanced (확장) | 아직 유효한 서명 캐시가 있을 때만 허용 (판정 발급 후 최대 30초) | **차단** (캐시로는 쓰기를 허용하지 않음) |

폴백을 켜면 달라진다. 조직 indexer의 새 서명 판정은 모드와 관계없이 쓰기도 허용할 수 있고, 직접 RPC 조회는 strict에서도 읽기 전용 호출을 허용할 수 있다([`apps/gateway/src/signed-admission.mjs:222-237`](../apps/gateway/src/signed-admission.mjs#L222-L237), [`apps/gateway/src/admission-fallback.mjs:55`](../apps/gateway/src/admission-fallback.mjs#L55)). 본선 데모는 폴백을 켜지 않는다.

읽기/쓰기 구분은 도구 선언(`readOnlyHint=true`, `destructiveHint=false`)으로 한다. 이 선언은 도구 표면 해시에 포함되므로 검증 뒤에 몰래 바꾸면 차단된다. 다만 처음부터 쓰기 도구를 읽기로 거짓 선언하는 것은 검사 단계에서 잡아야 한다.

## Reason

- 재확인은 **사용자가 기다리는 실행 경로** 위에 있다. 검증(릴리스당 1번, 실행 경로 밖)과 달리 비용이 매 호출에 붙는다. 그래서 비용(지연)과 효과(폐기 반영 속도)를 숫자로 보고 정한다.
- strict는 체인에 폐기·격리가 반영된 뒤 **다음 호출부터** 막는다. 재사용 창을 두면 그만큼 늦어진다.
- 쓰기(메일 발송 등)는 한 번 나가면 되돌릴 수 없으므로 장애 중에도 허용하지 않는다. 읽기는 업무 연속성을 위해 짧은 서명 캐시를 선택적으로 허용한다.
- 문서의 "93 ms"는 **스캐너 실행 시간**(2026-09-04 스냅샷)이지 Gateway 지연이 아니다. Gateway 오버헤드로 인용하지 않는다.

## Alternatives considered

- **세션 시작 때 1번만 확인:** 빠르지만 세션이 열려 있는 동안 폐기가 반영되지 않는다.
- **N초 재사용을 지금 고정(예: 30초):** 측정 근거 없이 노출 시간을 정하게 된다. 측정 후 결정한다.
- **체인 이벤트를 Gateway로 즉시 push:** 반영이 가장 빠르지만 현재 Gateway에는 push 구독이 없다. 로드맵이다.
- **장애 시 읽기·쓰기 모두 허용(fail open):** 거부한다.

## Consequences

Gateway가 보장하는 것과 보장하지 않는 것:

| 보장한다 | 보장하지 않는다 |
|---|---|
| 폐기·격리가 체인에 반영되고 Gateway가 이를 읽은 뒤의 **다음 호출**을 막는다 | **이미 보낸 데이터**(이미 보낸 메일)를 되돌리지 못한다 |
| REVOKED 릴리스를 실행(spawn) **전에** 막는다 | 이미 판정을 통과해 진행 중인 호출을 되돌리지 못한다 |
| 판정 서버 장애 중 쓰기 호출을 허용하지 않는다(폴백을 켜지 않은 본선 구성 기준) | Gateway를 거치지 않고 MCP를 직접 연결한 경우(**우회**)는 통제 범위 밖이다 |
| 한 번 REVOKED를 본 Gateway는 같은 릴리스의 이후 허용을 거부한다(같은 Gateway 프로세스 안에서. 재시작 후에도 유지하려면 서명 캐시 파일 설정(`MCPSHIELD_ADMISSION_CACHE_FILE`, `.revoked` 기록)이 필요하다. 장면 하네스는 장면 3의 Gateway A `run`과 장면 4의 "기록이 있는 A"에만 이 파일을 켠다) | 이 기록은 **그 Gateway가 직접 본 폐기만** 지킨다. 운영사가 장악된 동안 일어난 폐기나 새로 설치한 Gateway에는 소용이 없다(장면 4에서 기록 없는 새 Gateway A는 위조 ALLOW를 받아들인다) |
| (stdio Gateway) 실행 중 세션에서 판정이 거부되면 그 호출을 전달하지 않고 **세션을 끝낸다**(MCP 서버 자식 프로세스도 종료). 다시 쓰려면 새 세션이 실행 전 판정을 통과해야 한다 | 거부 뒤 같은 세션의 다른 호출도 함께 끊긴다. 재연결은 Agent 쪽 몫이다 |
| — | push가 없으므로, 다음 호출이 오기 전에는 아무 일도 하지 않는다 |

- 폐기·격리 전파 시간 = 블록 포함 + 다음 호출이 올 때까지의 시간 + 판정 1회 지연. 차단 방향은 체인 조회기가 최신(head) 블록의 판정을 그대로 쓰므로 확정 대기가 붙지 않는다([`packages/contracts-sdk/src/v2-chain-reader.mjs:88-96`](../packages/contracts-sdk/src/v2-chain-reader.mjs#L88-L96)). 확정 대기는 새 ALLOW에만 붙는다.
- LOCAL_EVM(Ganache)은 즉시 채굴이라 측정값은 **하한**이다. Base Sepolia에서는 블록 시간(차단 방향)이 더해지고, 승인 방향은 확정 대기까지 더해진다.
- 재사용 창을 도입하더라도 서명 판정의 유효 시간(API 발급 최대 30초)을 넘을 수 없다.

### 측정표 (1차 멘토링 M2 요청 3가지)

환경: LOCAL_EVM(Ganache, 즉시 채굴. VERIFIED를 읽는 장면 1·2 동안만 5초마다 빈 블록), 스캐너 REPORT FIXTURE 대역, 두 회사가 같은 로컬 RPC 사용, 같은 호스트. 결과 JSON의 `environment`는 이를 `chain: LOCAL_EVM_GANACHE`, `scanner: REPORT_FIXTURE_TEST_DOUBLE`, `validators: SINGLE_INSTITUTION_DEMO`, `governance`(배포 결과 값), `validatorVerification: SIGNS_OPERATOR_TEMPLATE_NO_INDEPENDENT_RESCAN`, `rpc: ONE_SHARED_LOCAL_RPC_FOR_BOTH_COMPANIES`와 `limitations` 배열로 표시한다. 아래 수치는 깨끗한 작업 트리에서 실행한 공식 측정(커밋 `f85f8e8`, Windows 개발 PC·Node v24.13.0, 표본 50)이다: [결과 JSON](../benchmarks/results/consortium-scene-f85f8e8-2026-10-10T18-00-42-747Z.json). 다른 하드웨어·OS(예: Linux CI)에서는 달라질 수 있다.

(a) `list_messages` 도구 호출 1회 왕복 지연. 워밍업 3라운드 뒤, 세 대상(직접·A·B)을 번갈아 호출해 잰다. Gateway 경로에는 매 호출의 서명 판정(API → 체인 조회 → Ed25519 서명 → Gateway 검증)이 포함된다. 결과 필드: `measurements.toolCallLatencyMs.{direct,gatewayA,gatewayB}.{n,p50,p95,max}`.

| 경로 | p50 | p95 | max |
|---|---|---|---|
| MCP 직접 연결 (Gateway 없음) | 0.24 ms | 0.45 ms | 0.55 ms |
| Gateway A 경유 (운영사 API) | 62.87 ms | 80.56 ms | 126.36 ms |
| Gateway B 경유 (회사 B API) | 61.69 ms | 79.76 ms | 80.09 ms |

- 이 환경에서 Gateway를 거치면 호출당 p50 약 62 ms가 더해진다. 이 값에는 매 호출의 API 왕복·체인 조회·서명·검증이 모두 들어 있고, 구성 요소별 분해는 측정하지 않았다. 재사용 창을 둘지는 이 비용과 폐기 노출 시간을 함께 보고 정한다.
- stdio Gateway 기준이다. HTTP serve 모드(호출마다 재스냅샷·해싱·자식 프로세스 시작)는 측정하지 않았다.
- 결과 JSON에는 요약값(n·p50·p95·max)과 실패 호출 수(`failedCalls`, 테스트가 0을 단언)만 남고 호출별 원자료는 남지 않는다.
- Gateway A 경로에는 장면 전환용 로컬 프록시 1홉이 더해진다(테스트 장치). 따라서 A와 B의 차이를 운영사 비용이나 신뢰 모델의 비용으로 해석하지 않는다.

(b) 검증자 C가 체인에 직접 보낸 긴급 격리 거래의 영수증을 하네스가 확인한 시각부터, 이미 열린 세션의 호출이 처음 거부된 시각까지(`measurements.quarantinePropagationMs.{gatewayA,gatewayB}` = `msFromInclusionToRefusal`. 전송 시각 기준 `msFromSendToRefusal`도 함께 기록):

| 경로 | 결과 |
|---|---|
| Gateway A | 126 ms |
| Gateway B | 126 ms |

- (b)의 격리는 검증자가 **체인에 직접** 보낸다(운영사 관여 없음). 측정 해상도는 "폴링 간격 + 호출 1회"다.
- 첫 거부 호출의 이유는 Gateway stderr에서 가져온 `RELEASE_QUARANTINED (QUARANTINED)`이며(`refusalReason`, 판정 상태는 `refusalAdmission`), 테스트는 거부 이유가 격리(QUARANTINED)임을 단언한다. 테스트는 또 영수증 확인 뒤에 시작한 호출이 허용된 적이 없고, 전송 전에는 예상하지 못한 실패가 없었음을 단언한다. stdio Gateway는 거부한 세션을 끝낸다.
- 측정한 것은 긴급 격리의 전파뿐이다. 2-of-3 FAIL 폐기(장면 3)의 실행 중 세션 전파는 아직 측정하지 않았다. 장면 3은 새 Gateway 프로세스가 `run`으로 후보를 띄우기 전에 거부하는 것만 확인한다.

(c) 판정 서버 장애 시 읽기/쓰기 동작. 운영사 엔드포인트를 실제로 끊은 상태(소켓을 끊는 로컬 스위치)에서, 하네스 프로세스 안에서 Gateway 라이브러리의 `getAdmission`을 직접 호출해 확인한다(`method: IN_PROCESS_GATEWAY_LIBRARY_getAdmission`. 조직 indexer·직접 RPC 폴백은 명시적으로 끄고 캐시 파일은 행마다 지정). 다섯 행 모두 테스트가 단언한다(`scenes.operatorOutage.readWrite`).

| 경우 (Gateway A, 운영사 중단) | 결과 | 이유 |
|---|---|---|
| strict + 유효한 서명 캐시 / 읽기 | 차단 | `UNAVAILABLE_FAIL_CLOSED` (strict는 캐시를 쓰지 않음) |
| strict + 유효한 서명 캐시 / 쓰기 | 차단 | `UNAVAILABLE_FAIL_CLOSED` |
| balanced + 유효한 서명 캐시 / 읽기 | 허용 (`decisionSource: CACHE`) | — |
| balanced + 유효한 쓰기 캐시(별도로 `WRITE_EXTERNAL` 판정으로 채움) / 쓰기 | 차단 | `UNAVAILABLE_FAIL_CLOSED` (캐시로는 쓰기를 허용하지 않음) |
| balanced + 만료된 캐시(시계 +31초) / 읽기 | 차단 | `SIGNED_CACHE_EXPIRED` |

- 이와 별도로 실제 Gateway A 프로세스의 실행 중 세션은 장애 직후 다음 호출을 거부하고 세션을 끝낸다. Gateway B는 장애 중 실행 중 세션의 strict 도구 호출이 성공하는 것만 확인한다.
- 서버는 정상인데 판정만 만료된 경우는 이 하네스가 확인하지 않는다(기존 Gateway 테스트 범위). compose 스택에서는 아직 확인하지 않았다.
- 재사용 창 결정 규칙: (a)의 Gateway 추가 지연이 사용자에게 문제가 될 만큼 크고, (b)의 노출 시간이 늘어나는 것을 컨소시엄이 받아들일 때만 도입한다.

## Evidence / verification

- 매 `tools/call` 재확인: [`apps/gateway/src/protocol-guard.mjs:152`](../apps/gateway/src/protocol-guard.mjs#L152), [`apps/gateway/src/index.mjs:270-278`](../apps/gateway/src/index.mjs#L270-L278)
- 허용 판정의 만료 확인(lease): [`apps/gateway/src/protocol-guard.mjs:21-30`](../apps/gateway/src/protocol-guard.mjs#L21-L30)
- 서명 판정 유효 시간 상한 30초: [`apps/api/src/control-plane.ts:312`](../apps/api/src/control-plane.ts#L312). Gateway 쪽 검사: [`apps/gateway/src/signed-admission.mjs:95-98`](../apps/gateway/src/signed-admission.mjs#L95-L98)
- 장애 시 동작(balanced 읽기 전용, 그 외 fail closed): [`apps/gateway/src/signed-admission.mjs:202-239`](../apps/gateway/src/signed-admission.mjs#L202-L239)
- REVOKED 기억: [`apps/gateway/src/signed-admission.mjs:243-253`](../apps/gateway/src/signed-admission.mjs#L243-L253)
- 읽기/쓰기 분류: [`apps/gateway/src/index.mjs:241-243`](../apps/gateway/src/index.mjs#L241-L243). 선언이 표면 해시에 포함됨: [`apps/gateway/src/artifact.mjs:19-26`](../apps/gateway/src/artifact.mjs#L19-L26)
- 우회는 범위 밖: [`docs/threat-model.md:42`](threat-model.md#L42)(잔여 위험), [`:59`](threat-model.md#L59)(비목표). 직접 실행 시도는 남용 사례로 [`:53`](threat-model.md#L53)에 있다
- "93 ms"의 출처(스캐너 시간): [`docs/evaluation.md:50`](evaluation.md)
- 거부 시 세션 종료: [`apps/gateway/src/index.mjs:342-355`](../apps/gateway/src/index.mjs#L342-L355)(`gateway_runtime_blocked` 기록 후 자식 프로세스 종료)
- 측정: [`tests/integration/consortium-scene.ts`](../tests/integration/consortium-scene.ts)(불변 조건 `assertConsortiumReport`), `npm run evaluate:consortium-scene` → `benchmarks/results/consortium-scene-<sha7>-<timestamp>.json`(`--allow-dirty`로 실행하면 이름에 `-dirty-<소스 해시 8자리>`가 붙는다)
