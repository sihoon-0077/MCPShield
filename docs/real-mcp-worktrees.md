# Real MCP development worktrees

The original `ai블록체인해커톤` directory and its worktrees remain unchanged. This development line starts from GitHub commit `0831a55` in separate directories.

| Role | Branch | Worktree | Responsibility |
|---|---|---|---|
| Main | `mcp/main` | `MCPShield-real-mcp-main` | interface decisions, merge, full E2E |
| Security·AI | `mcp/security-ai` | `MCPShield-real-mcp-security-ai` | real MCP fixtures, scanner evidence, reviewed hashes |
| Blockchain·Backend | `mcp/blockchain-backend` | `MCPShield-real-mcp-blockchain-backend` | admission invariants backed by release state |
| Frontend·Gateway·DevOps | `mcp/frontend-gateway-devops` | `MCPShield-real-mcp-frontend-gateway-devops` | Gateway transport and official MCP client harness |
| Reviewer | `mcp/reviewer` | `MCPShield-real-mcp-reviewer` | read-only review after integration |

## Real MCP acceptance

1. The official MCP TypeScript client launches MCPShield Gateway over stdio.
2. Gateway computes the artifact identity and checks admission before it starts the MCP server.
3. `mail-mcp@1.0.0` completes `initialize`, `tools/list`, and `tools/call` through Gateway.
4. The runtime `tools/list` response matches the reviewed manifest hash.
5. `mail-mcp@1.0.1` is rejected before its process starts.
6. The official MCP client reaches `/mcp` over Streamable HTTP, sees `list_messages` as read-only, executes `1.0.0`, and receives a tool error for revoked `1.0.1`.

The remote endpoint is a transport wrapper around the exact local artifact. It does not claim to attest arbitrary mutable remote MCP servers.
