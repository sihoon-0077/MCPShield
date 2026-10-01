# ADR-001: Exact local stdio release is the MVP trust unit

- Status: Accepted
- Scope: Hackathon MVP

## Decision

The MVP trust unit remains an exact local stdio MCP release represented by a canonical release ID, artifact digest, and tool-surface hash. A Streamable HTTP Gateway may expose that verified local artifact to remote clients such as ChatGPT. Arbitrary third-party remote MCP endpoints are not claimed to have runtime-code attestation.

## Reason

A local artifact can be fetched, hashed, scanned, executed in an isolated test environment, and checked again before spawn. A remote operator can replace server-side code without changing the client-visible URL or metadata.

## Consequences

- The demo can make a strong and testable allow/block claim.
- Automatic support for every remote MCP implementation and package ecosystem is deferred.
- Gateway enforcement must compare both artifact and tool-surface hashes.
- Product messaging must distinguish local exact-artifact assurance from remote metadata monitoring.

