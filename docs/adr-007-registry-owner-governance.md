# ADR-007: 레지스트리 owner 권한 — MVP는 단일 관리자, 운영은 컨소시엄 멀티시그

- Status: Accepted
- Scope: V2 컨트랙트(`ValidatorRegistry`, `PolicyRegistry`, `ReleaseRegistryV2`)의 관리자 권한 운영
- Date: 2026-10-11
- Related: 1차 멘토링(2026-10) M6, M12, M18, M19

## Decision

- **MVP:** 배포 지갑 하나가 관리자(owner)다. 데모에서는 Ganache 테스트 계정 0번이다. 이것을 숨기지 않고 공개한다.
- **MVP의 owner는 운영사 relayer 핫키이기도 하다.** 릴리스 등록·정책 게시·폐지가 owner 전용인데 이 거래를 운영사 API의 relayer가 보내므로, 운영사 API 프로세스가 쥔 relayer 키가 곧 owner 키다([`apps/api/src/chain-outbox.ts:52-54`](../apps/api/src/chain-outbox.ts#L52-L54), [`apps/api/src/control-config.ts:60`](../apps/api/src/control-config.ts#L60), [`contracts/scripts/deploy-v2.ts:20-23`](../contracts/scripts/deploy-v2.ts#L20-L23)). 장면 하네스도 계정 0번을 배포자와 relayer로 함께 쓴다. 그래서 운영사 API 프로세스 전체가 장악되면 REVOKED→VERIFIED는 여전히 불가하고 체인을 읽는 Gateway B는 REVOKED를 계속 차단하지만, `disable`·`deprecate`로 정상 릴리스까지 A·B 모두 fail closed될 수 있다(서비스 거부).
- **운영 계획:** 컨소시엄 참여사들의 멀티시그(예: Safe 3-of-5)를 관리자로 두고 배포한다. owner(멀티시그)와 relayer 키를 분리하고, relayer는 검증자 서명 제출과 긴급 격리 제출만 맡는다. 다음 컨트랙트 버전에서 `deprecate`·`registerRelease`에는 타임락을 두고, `disable`은 키 유출 대응용이라 짧은 지연 또는 멀티시그 정족수로 제한한다. 비상 절차를 문서화한다.
- 핵심 사실: **owner 키가 탈취되어도 체인의 REVOKED를 VERIFIED로 바꿀 수 없다.** owner의 즉시 권한은 서비스 거부(fail closed)를 일으킬 수 있지만 거짓 허용을 만들지는 못한다. 다만 1일 지연 뒤에는 검증자 교체로 거짓 VERIFIED를 만들 수 있다(아래 Reason).

### owner가 할 수 있는 것 (코드 기준)

owner 자리는 3개(`ValidatorRegistry`, `PolicyRegistry`, `ReleaseRegistryV2`)이고 모두 배포 때 정해지며 바꿀 수 없다(immutable).

| 권한 | 지연 | 효과 |
|---|---|---|
| 릴리스 등록 `registerRelease` | 즉시 | 정확한 신원(digest 4종)을 등록한다. 등록만으로는 VERIFIED가 아니며 검증자 2명의 PASS가 필요하다 |
| 정책 게시 `publish` | 즉시 | 게시된 정책 내용은 이후 바꿀 수 없다 |
| 정책 폐지 `deprecate` | 즉시, 되돌릴 수 없음 | 그 정책의 VERIFIED가 모두 EXPIRED로 읽힌다. 새 판정·격리도 막힌다 |
| 검증자 교체 예약 `scheduleRotation` | **1일 고정** | 1일 뒤 누구나 `rotate()`를 호출할 수 있다. 취소 함수는 없고, 다시 예약하면 덮어쓰며 1일이 새로 시작된다 |
| 검증자 비활성화 `disable` | 즉시, 되돌릴 수 없음 | 검증자 집합 버전이 올라가 **모든 릴리스의 VERIFIED가 동시에 EXPIRED**가 된다 |

참고: 정상적인 교체(`rotate`)도 버전을 올리므로 교체 뒤에는 모든 릴리스를 다시 검증해야 한다.

### owner가 할 수 없는 것

- REVOKED 되돌리기 (폐기 표시는 켜기만 가능)
- 판정·투표를 직접 쓰기 (검증자 서명 필요). 본인이 활성 검증자가 아니면 판정 제출·격리 불가. 단, 1일 뒤 교체로 자기 키를 검증자로 넣으면 가능하다
- 등록된 릴리스 신원의 수정·삭제
- `disable` 복구, 정책 폐지 취소
- 소유권 이전(함수 없음), 컨트랙트 업그레이드(업그레이드 불가 배포)
- 교체 지연 1일 단축, 정족수 2명·검증자 3명 변경, 격리 조기 종료

## Reason

- 캡스톤 MVP에서 관리자 하나는 현실적인 선택이다. 다만 한 키가 등록·정책·검증자 교체를 모두 쥐는 구조는 운영에서는 단일 실패 지점이므로, 운영 계획을 지금 명시한다.
- 탈취된 owner가 할 수 있는 최악의 일을 정확히 적어야 위험을 과장하지도 축소하지도 않는다.
  - **즉시:** `disable`·`deprecate`로 VERIFIED를 한꺼번에 만료시킬 수 있다. Gateway는 fail closed로 차단한다(업무 정지). 검증자 2명만 비활성화해도 다음 교체(최소 1일)까지 정족수 2명을 채울 수 없다.
  - **1일 뒤:** 공격자 키로 검증자 교체를 발효시켜 **REVOKED가 아닌 모든 릴리스(새로 등록한 악성 릴리스 포함)** 에 거짓 VERIFIED를 만들 수 있다([`ReleaseRegistryV2.sol:134`](../contracts/src/ReleaseRegistryV2.sol#L134), [`:149-155`](../contracts/src/ReleaseRegistryV2.sol#L149-L155)). 다만 (1) 교체 예약 이벤트가 체인에 공개되어 1일 동안 탐지할 수 있고(새 검증자 주소는 이벤트에는 없지만 `scheduleRotation` 거래 입력값으로 확인할 수 있다. 지금은 감시 코드가 없다), (2) Gateway는 검증자 집합 버전을 고정하므로 버전이 바뀌면 사람이 재설정하기 전까지 판정을 거부(fail closed)하고, (3) 이미 REVOKED된 릴리스는 어떤 경우에도 되살릴 수 없다.

## Alternatives considered

- **MVP부터 멀티시그 배포:** 가장 안전하지만 데모 준비 시간 대비 효과가 작다. 데모의 검증자도 팀 운영이므로([ADR-003](adr-003-validator-consortium.md)) 관리자만 분리해도 독립성 주장이 생기지 않는다.
- **owner 권한 제거(완전 무관리자):** 탈취된 검증자 키를 막을 비상 수단(`disable`)도 사라진다.
- **모든 권한에 긴 타임락:** `disable`은 탈취된 검증자 키를 막는 비상 수단이라 지연을 길게 둘 수 없다. 짧은 지연과 멀티시그 정족수의 조합을 다음 버전에서 검토한다.

## Consequences

| 항목 | MVP (지금) | 운영 계획 (미구현) |
|---|---|---|
| 관리자 | 단일 배포 지갑(= 운영사 relayer 키), 공개 | 컨소시엄 멀티시그 (예: Safe 3-of-5). relayer 키와 분리 |
| 적용 방법 | — | owner가 immutable이므로 **재배포** 필요. 검증자·정책 레지스트리는 `V2_GOVERNANCE_ADMIN`으로 멀티시그 주소를 이미 줄 수 있다(재배포만 필요). `ReleaseRegistryV2`는 owner가 항상 배포 지갑이라 스크립트 수정이 필요하다. 또 운영사 relayer가 보내던 정책 게시·폐지·릴리스 등록([`chain-outbox.ts:52-54`](../apps/api/src/chain-outbox.ts#L52-L54))을 멀티시그 제안 흐름으로 바꿔야 한다(그대로 두면 `ONLY_OWNER`로 실패) |
| 즉시 권한 (`disable`·`deprecate`·`registerRelease`) | 타임락 없음 | 다음 컨트랙트 버전에서 `deprecate`·`registerRelease`는 타임락, `disable`은 짧은 지연 또는 멀티시그 정족수 |
| 거버넌스 이벤트 감시 | 없음 (indexer가 교체·비활성화·폐지 이벤트를 보지 않음) | 교체 예약·비활성화·정책 폐지 알림 |
| 비상 절차 | 이 문서의 계획만 있음, 훈련 안 함 | 아래 절차를 문서화하고 훈련 |

비상 절차 (계획):

1. **검증자 키 탈취:** `disable`(즉시) → 새 검증자 교체 예약 → 1일 뒤 `rotate` → 모든 릴리스 재검증 → Gateway의 검증자 집합 버전 설정 갱신.
2. **예정에 없던 교체 예약 발견:** Gateway의 검증자 집합 버전 설정을 올리지 않는다(fail closed 유지). 컨소시엄에 공지한다.
3. **owner 키 탈취 확정:** 새 멀티시그로 재배포 → 정책 게시·릴리스 재등록·재검증 → Gateway의 레지스트리 주소·버전 교체.

미해결: 재배포하면 기존 컨트랙트의 REVOKED 기록이 새 컨트랙트로 자동 이전되지 않는다. 폐기 이력을 새 컨트랙트에서 다시 기록할지, Gateway가 이전 컨트랙트의 폐기 기록도 함께 확인할지는 아직 정하지 않았다. 가스 비용, 키 교체 구현, 정책 버전 관리와 함께 다음 멘토링에서 다룬다.

## Evidence / verification

- owner 자리 3개, 모두 immutable: [`ReleaseRegistryV2.sol:5`](../contracts/src/ReleaseRegistryV2.sol#L5), [`:52`](../contracts/src/ReleaseRegistryV2.sol#L52), [`:91`](../contracts/src/ReleaseRegistryV2.sol#L91)
- `registerRelease` owner 전용, 신원 덮어쓰기 불가: [`:116-123`](../contracts/src/ReleaseRegistryV2.sol#L116-L123)
- 정책 게시·폐지: [`:59-68`](../contracts/src/ReleaseRegistryV2.sol#L59-L68). 폐지의 효과: [`:137`](../contracts/src/ReleaseRegistryV2.sol#L137), [`:183`](../contracts/src/ReleaseRegistryV2.sol#L183), [`:199-203`](../contracts/src/ReleaseRegistryV2.sol#L199-L203)
- 교체 예약(1일 고정)과 누구나 호출하는 `rotate`: [`:29-42`](../contracts/src/ReleaseRegistryV2.sol#L29-L42)
- `disable` 즉시·전역 버전 증가: [`:43-48`](../contracts/src/ReleaseRegistryV2.sol#L43-L48). VERIFIED는 현재 버전일 때만: [`:198-203`](../contracts/src/ReleaseRegistryV2.sol#L198-L203). 테스트: [`tests/contracts/release-registry-v2.test.ts:44-46`](../tests/contracts/release-registry-v2.test.ts#L44-L46)
- REVOKED는 켜기만 가능: [`:161`](../contracts/src/ReleaseRegistryV2.sol#L161), [`:196`](../contracts/src/ReleaseRegistryV2.sol#L196). 정족수 2명 고정: [`:160-166`](../contracts/src/ReleaseRegistryV2.sol#L160-L166)
- 배포 스크립트: `ReleaseRegistryV2` owner = 배포 지갑, 업그레이드 불가: [`contracts/scripts/deploy-v2.ts:20-25`](../contracts/scripts/deploy-v2.ts#L20-L25)
- Gateway의 검증자 집합 버전 고정 검사: [`apps/gateway/src/signed-admission.mjs:86-89`](../apps/gateway/src/signed-admission.mjs#L86-L89)
- 자체 감사의 FR-211(교체 거버넌스) "부분" 표시: [`docs/MASTER_REQUIREMENTS_AUDIT_2026-09-19.md`](MASTER_REQUIREMENTS_AUDIT_2026-09-19.md)
