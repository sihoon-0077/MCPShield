# ADR-001: Exact local stdio release is the MVP trust unit

- Status: Accepted
- Scope: Hackathon MVP

## Decision

The MVP supports exact local stdio MCP releases represented by a canonical release ID, artifact digest, and tool-surface hash. Remote MCP endpoints are displayed only with a lower assurance level and are not claimed to have runtime-code attestation.

## Reason

A local artifact can be fetched, hashed, scanned, executed in an isolated test environment, and checked again before spawn. A remote operator can replace server-side code without changing the client-visible URL or metadata.

## Consequences

- The demo can make a strong and testable allow/block claim.
- Automatic support for every MCP transport and package ecosystem is deferred.
- Gateway enforcement must compare both artifact and tool-surface hashes.
- Product messaging must distinguish local exact-artifact assurance from remote metadata monitoring.

