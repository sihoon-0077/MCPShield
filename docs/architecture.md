# MCPShield MVP Architecture

## Scope

MVP는 고정된 로컬 MCP fixture의 릴리스를 등록하고, 외부 scanner 결과를 저장하고, 검증자 정족수로 상태를 확정하고, Gateway가 실행 전 admission 결정을 조회할 수 있는 수직 흐름을 제공한다.

## Components

```text
Scanner Result
    -> Backend API
        -> Release/Scan Store
        -> Validator Votes
        -> ReleaseRegistry Contract
        -> Chain Event Indexer
    -> Admission API
        -> Gateway
    -> Dashboard API
```

## Trust Boundaries

- Scanner output은 신뢰 입력이 아니므로 API에서 schema validation을 수행한다.
- Validator identity와 중복 투표는 컨트랙트 및 API 양쪽에서 검증한다.
- raw evidence는 오프체인에 저장하고 체인에는 hash와 상태만 기록한다.
- Gateway는 `UNVERIFIED`, `QUARANTINED`, `REVOKED`, digest mismatch를 차단한다.
- demo private key는 로컬 개발 전용이며 저장소에 실제 운영 키를 넣지 않는다.

## State Ownership

- API/DB: 요청, scan 결과, 검증자 판정, chain projection
- Contract: 릴리스 상태와 정족수 판정의 공개 기록
- Indexer: contract event를 API 조회용 projection으로 반영
- Scanner: finding과 evidence hash 생성
- Gateway: 최종 admission 결정을 집행

