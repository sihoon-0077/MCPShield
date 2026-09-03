# MCPShield Integration Checklist

## Contract and API

- [ ] API enum과 Solidity enum의 상태 순서가 문서화되어 있다.
- [ ] 동일 validator의 중복 투표가 거부된다.
- [ ] 등록되지 않은 validator의 투표가 거부된다.
- [ ] 첫 FAIL이 `QUARANTINED`를 만든다.
- [ ] 두 번째 FAIL이 `REVOKED`를 만든다.
- [ ] `REVOKED` 상태는 되돌릴 수 없다.
- [ ] 모든 상태 변경에 event가 발생한다.

## Data and Validation

- [ ] Scan Result가 공통 JSON Schema로 검증된다.
- [ ] digest와 hash 형식 오류가 거부된다.
- [ ] raw evidence와 개인정보가 온체인에 저장되지 않는다.
- [ ] DB migration이 빈 데이터베이스에서 성공한다.
- [ ] event projection을 재구축할 수 있다.

## Admission

- [ ] `VERIFIED`와 일치하는 digest만 `ALLOW`된다.
- [ ] `UNVERIFIED`, `QUARANTINED`, `REVOKED`는 `BLOCK`된다.
- [ ] digest mismatch는 `BLOCK`된다.
- [ ] 상태 조회 실패 시 명시적인 fail mode를 반환한다.
- [ ] 응답이 `LIVE`, `MOCK`, `REPLAY`를 구분한다.

## Demo

- [ ] safe 1.0.0 흐름이 재현된다.
- [ ] malicious 1.0.1 흐름이 재현된다.
- [ ] 체인 tx 또는 로컬 chain event를 확인할 수 있다.
- [ ] clean reset부터 전체 데모가 한 명령 흐름으로 실행된다.
- [ ] 실제 secret이 `.env`, 로그, fixture에 존재하지 않는다.
- [ ] 테스트와 데모 실행 방법이 README에 있다.
