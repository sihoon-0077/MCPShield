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

## Compatibility Rules

1. 모든 JSON payload는 `schemaVersion`을 포함한다.
2. 알 수 없는 enum 값은 허용하지 않는다.
3. hash와 address는 저장 전 정규화한다.
4. API는 scanner의 임의 내부 필드를 신뢰하지 않고 schema validation을 수행한다.
5. 체인에 raw evidence나 개인정보를 기록하지 않는다.
