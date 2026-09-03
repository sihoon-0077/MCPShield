# MCPShield Interface Contract v1

이 문서는 병렬 구현에서 사용하는 최소 공통 계약이다. 호환되지 않는 변경은 Main 승인 후 새 schema version으로 추가한다.

## Identifiers

- `releaseId`: `<packageName>@<semver>` 형식의 문자열
- `artifactDigest`: `sha256:<64 lowercase hex>`
- `toolSurfaceHash`: `0x<64 lowercase hex>`
- `scanId`: UUID
- `evidenceHash`: `0x<64 lowercase hex>`

## Release Status

```text
UNVERIFIED -> VERIFIED
UNVERIFIED -> QUARANTINED
VERIFIED   -> QUARANTINED
QUARANTINED -> REVOKED
```

`REVOKED`는 동일 `releaseId`에서 되돌리지 않는다. 수정된 코드는 새로운 버전과 새로운 `releaseId`로 등록한다.

## Scan Status

```text
QUEUED | RUNNING | PASSED | FAILED | INCONCLUSIVE
```

## Finding Codes

```text
SENSITIVE_FILE_READ
UNDECLARED_EGRESS
CANARY_EXFILTRATION
TOOL_SURFACE_CHANGED
SEMANTIC_BEHAVIOR_MISMATCH
```

## Finding Severity

```text
INFO | LOW | MEDIUM | HIGH | CRITICAL
```

## Validator Decision

```text
PASS | FAIL | ABSTAIN
```

## Admission Decision

```json
{
  "releaseId": "mail-mcp@1.0.1",
  "decision": "BLOCK",
  "releaseStatus": "REVOKED",
  "reasonCode": "RELEASE_REVOKED",
  "checkedAt": "2026-01-01T00:00:00.000Z",
  "source": "LIVE"
}
```

`source`는 `LIVE`, `MOCK`, `REPLAY` 중 하나다.

## Register Release Request

관리자 전용 요청이다. `Authorization: Bearer <ADMIN_API_TOKEN>`이 필요하다.

```json
{
  "schemaVersion": "1.0.0",
  "releaseId": "mail-mcp@1.0.1",
  "artifactDigest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "toolSurfaceHash": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
}
```

## Submit Scan Request

scanner service 전용 요청이다. `Authorization: Bearer <SCANNER_API_TOKEN>`이 필요하다. 클라이언트는 `source`를 보내지 않으며, 서버가 인증된 입력을 `LIVE`로 기록한다.

```json
{
  "schemaVersion": "1.0.0",
  "scanId": "018f5f9d-f1d2-7abc-8def-1234567890ab",
  "releaseId": "mail-mcp@1.0.1",
  "artifactDigest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "toolSurfaceHash": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "scanStatus": "FAILED",
  "findings": [],
  "evidenceHash": "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
}
```

## Submit Attestation Request

validator는 API에 private key를 제공하지 않는다. validator CLI가 EIP-712 typed data에 서명하고 API는 서명을 relay한다.

```json
{
  "schemaVersion": "1.0.0",
  "releaseId": "mail-mcp@1.0.1",
  "scanId": "018f5f9d-f1d2-7abc-8def-1234567890ab",
  "decision": "FAIL",
  "evidenceHash": "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
  "nonce": 0,
  "deadline": 1893456000,
  "signature": "0x..."
}
```

서명 domain에는 `chainId`와 `verifyingContract`가 포함되며, message에는 release key, decision, evidence hash, nonce, deadline이 포함된다.

## Admission Request

```json
{
  "schemaVersion": "1.0.0",
  "releaseId": "mail-mcp@1.0.1",
  "artifactDigest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "toolSurfaceHash": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
}
```

Admission은 DB와 온체인의 status, artifact digest, tool-surface hash가 모두 일치할 때만 `ALLOW`한다.

## Compatibility Rules

1. 모든 JSON payload는 `schemaVersion`을 포함한다.
2. 알 수 없는 enum 값은 허용하지 않는다.
3. hash와 address는 저장 전 정규화한다.
4. API는 scanner의 임의 내부 필드를 신뢰하지 않고 schema validation을 수행한다.
5. 체인에 raw evidence나 개인정보를 기록하지 않는다.
6. 관리자와 scanner credential은 서로 분리하고 알려진 기본값을 허용하지 않는다.
7. validator nonce는 온체인 값을 기준으로 reconciliation할 수 있어야 한다.
