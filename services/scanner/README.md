# MCPShield Security Scanner

Node.js 표준 라이브러리만 사용하는 MVP scanner다. 고정 fixture의 digest와 tool surface를 계산하고, 정적 규칙·선택적 AI 분석·격리 실행 evidence를 공통 `ScanResult` v1 JSON으로 출력한다. AI 결과만으로 `FAILED`를 만들지 않으며 AI 장애 시에도 결정론적 결과는 유지한다.

## Run

저장소 루트에서 실행한다.

```powershell
node services/scanner/src/cli.mjs --fixture demo/fixtures/mail-mcp-1.0.0
node services/scanner/src/cli.mjs --fixture demo/fixtures/mail-mcp-1.0.1 --baseline demo/fixtures/mail-mcp-1.0.0
node --test tests/security/scanner.test.mjs
node benchmarks/evaluate.mjs --runs 10
```

정상 fixture는 `PASSED`와 빈 finding을 반환한다. 악성 fixture는 `FAILED`와 아래 결정론적 finding을 반환하며 raw canary는 결과나 로그에 남기지 않는다.

```text
SENSITIVE_FILE_READ
UNDECLARED_EGRESS
CANARY_EXFILTRATION
TOOL_SURFACE_CHANGED
```

## AI analyzer

`--ai-url http://127.0.0.1:PORT` 또는 `MCP_SHIELD_AI_URL`을 지정하면 `{ "prompt": "..." }` POST 요청을 보낸다. 응답은 `{ "findings": [...] }`여야 하며 각 finding은 공통 schema와 다음 제한을 만족해야 한다.

```text
code=SEMANTIC_BEHAVIOR_MISMATCH
stage=AI
deterministic=false
```

인증이 필요하면 `MCP_SHIELD_AI_TOKEN` 환경 변수를 사용한다. timeout 또는 잘못된 JSON은 `ai_analysis_failed` 로그만 남기며 정적·sandbox 단계는 계속된다.

## Docker isolation

Docker가 있는 환경에서는 `--sandbox docker`를 추가한다. scanner는 외부 통신이 차단된 임시 `--internal` network를 만들고, read-only filesystem, drop-all capabilities, `no-new-privileges`, memory/CPU/PID 제한으로 fixture와 local exfil sink를 실행한 뒤 컨테이너와 network를 제거한다.

```powershell
node services/scanner/src/cli.mjs --fixture demo/fixtures/mail-mcp-1.0.1 --baseline demo/fixtures/mail-mcp-1.0.0 --sandbox docker --sandbox-timeout-ms 5000
```

Docker를 사용할 수 없거나 sandbox가 timeout이면 결과는 `INCONCLUSIVE`다. 로컬 개발 기본값인 `local`은 재현용 child process이며 강제 격리가 필요할 때는 반드시 Docker mode를 사용한다. 기능 비활성화는 AI URL을 제거하고 `--sandbox local`로 되돌리면 된다.

## Sample result

```json
{
  "schemaVersion": "1.0.0",
  "scanId": "123e4567-e89b-42d3-a456-426614174000",
  "releaseId": "mail-mcp@1.0.1",
  "artifactDigest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "toolSurfaceHash": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "scanStatus": "FAILED",
  "findings": [
    {
      "code": "CANARY_EXFILTRATION",
      "severity": "CRITICAL",
      "deterministic": true,
      "stage": "SANDBOX",
      "message": "Dummy canary reached the controlled local sink.",
      "evidence": { "sink": "CONTROLLED_LOCAL" }
    }
  ],
  "evidenceHash": "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
  "source": "LIVE"
}
```

hash 값은 설명용이다. 실제 실행 결과는 artifact와 sanitized evidence에서 계산된다.
