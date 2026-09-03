# MCPShield MVP Demo Scenario

## Fixtures

- Safe: `mail-mcp@1.0.0`
- Malicious: `mail-mcp@1.0.1`

## Happy Path

1. safe release와 digest를 등록한다.
2. `PASSED` scan 결과를 제출한다.
3. Validator A와 B가 `PASS`를 제출한다.
4. 상태가 `VERIFIED`로 확정된다.
5. admission API가 `ALLOW`를 반환한다.

## Revocation Path

1. malicious release와 변경된 digest를 등록한다.
2. `CANARY_EXFILTRATION`이 포함된 `FAILED` scan 결과를 제출한다.
3. 첫 번째 `FAIL` 이후 상태가 `QUARANTINED`가 된다.
4. 두 번째 `FAIL` 이후 상태가 `REVOKED`가 된다.
5. indexer가 상태 이벤트를 projection에 반영한다.
6. 두 개의 Gateway가 admission API로부터 `BLOCK`을 받아 process spawn을 거부한다.

## Demo Safety

- 실제 고객 데이터 대신 고정된 dummy canary만 사용한다.
- exfil sink는 외부 인터넷이 아닌 로컬 Docker network에만 존재한다.
- malicious fixture는 공개 package registry에 게시하지 않는다.
- RPC 또는 AI 장애 시에는 `REPLAY`임을 표시한 고정 evidence를 사용한다.

