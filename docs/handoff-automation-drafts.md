# 미활성 자동화 초안 보관

기준일: 2026-09-10. Backend 작업 공간에 미추적 파일로 남아 있던 두 초안을 그대로 보관한다.
**이 문서는 GitHub Actions workflow가 아니며 예약 실행/알림/추가 CI를 활성화하지 않는다.**

활성 검증 구성은 [기존 workflow](../.github/workflows/frontend-gateway-devops.yml)다.
다음 담당자는 그대로 복사하기 전에 다음을 해결해야 한다.

- ci 초안은 기존 검사와 중복된다. `test:backend`에 API 테스트가 포함돼 추가 `test:api`가 중복 실행된다.
- full-integration의 `main/master` 조건은 최신 개발 브랜치 `master/main`과 다르다.
- healthcheck 초안은 GET 성공만 확인하며 DB/체인/스캐너의 종합 상태나 실제 MCP handshake를 증명하지 않는다.
- curl의 전체/연결 timeout, 응답 계약 검증, 알림 중복 억제·복구 알림, 전송 실패 처리를 검토해야 한다.
- 예약 workflow는 기본 브랜치에 존재해야 하며, 현재 기본 `main`과 개발 `master/main`의 관계를 확인해야 한다.
- 수신자/webhook과 실제 알림 전달은 구성·검증되지 않았다. 사용자의 승인된 알림 범위와 운영 대상 확인 후 활성화한다.
- 원래 로컬 파일은 수정·삭제하지 않았다. 아래 코드는 원본 보관이며 검증 완료 코드가 아니다.

## ci.yml 원본

```yaml
name: MCPShield CI

on:
  push:
  pull_request:
  workflow_dispatch:

concurrency:
  group: mcpshield-ci-${{ github.ref }}
  cancel-in-progress: true

jobs:
  quick-check:
    runs-on: ubuntu-latest
    timeout-minutes: 20
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Set up Node.js
        uses: actions/setup-node@v4
        with:
          node-version: "22"
          cache: "npm"

      - name: Install dependencies
        run: npm ci

      - name: Backend type check
        run: npm run build:backend

      - name: Backend unit tests
        run: npm run test:backend

      - name: API tests
        run: npm run test:api

      - name: Gateway tests
        run: npm run test:gateway

      - name: Dashboard build
        run: npm run build:dashboard

      - name: Validate docker-compose
        run: npm run stack:config

  full-integration:
    if: github.ref_name == 'main' || github.ref_name == 'master'
    runs-on: ubuntu-latest
    timeout-minutes: 40
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Set up Node.js
        uses: actions/setup-node@v4
        with:
          node-version: "22"
          cache: "npm"

      - name: Install dependencies
        run: npm ci

      - name: E2E-like API smoke (no external credentials)
        run: npm run demo:evm-smoke
```

## healthcheck.yml 원본

```yaml
name: MCPShield Health Check

on:
  schedule:
    - cron: "*/10 * * * *"
  workflow_dispatch:

jobs:
  smoke-endpoints:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - name: Check public endpoints
        env:
          HEALTHCHECK_BASE: ${{ vars.MCPSHIELD_HEALTHCHECK_BASE }}
          HEALTH_NOTIFY_WEBHOOK: ${{ secrets.MCPSHIELD_HEALTH_NOTIFY_WEBHOOK }}
        run: |
          BASE="${HEALTHCHECK_BASE:-https://mcpshield-judge-lab-production.up.railway.app}"
          echo "Check base=$BASE"

          check_fail=0

          if ! curl -fsS "$BASE/health" > /tmp/health.json; then
            echo "API /health failed"
            check_fail=1
          fi

          if ! curl -fsS "$BASE/mcp" > /tmp/mcp.html; then
            echo "Gateway /mcp failed"
            check_fail=1
          fi

          if [ "$check_fail" -ne 0 ]; then
            if [ -n "$HEALTH_NOTIFY_WEBHOOK" ]; then
              curl -X POST -H "Content-Type: application/json" \
                -d "{\"text\":\"[MCPShield] Health check failed: $BASE /health or /mcp not reachable\"}" \
                "$HEALTH_NOTIFY_WEBHOOK"
            fi
            exit 1
          fi

          echo "Health check passed"
```
