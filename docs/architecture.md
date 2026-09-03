# MCPShield MVP Architecture

## Scope

The MVP admits exact local stdio MCP releases. It does not create another registry, token, DAO, or universal remote attestation system.

```mermaid
flowchart LR
    subgraph Control["Control plane"]
      F["Exact fixture"] --> S["Static rules"]
      F --> AI["Structured AI analysis"]
      F --> SB["Sandbox observer"]
      S --> E["Canonical evidence bundle"]
      AI --> E
      SB --> E
    end
    subgraph Trust["Trust plane"]
      E --> V["Independent validators"]
      V -->|"EIP-712 votes"| C["ReleaseRegistry 2-of-3"]
      C --> I["Indexer / reconciliation"]
    end
    subgraph Data["Execution plane"]
      I --> API["Admission API"]
      API --> G["stdio Gateway"]
      G -->|"ALLOW"| MCP["MCP child process"]
      G -->|"BLOCK"| D["Execution denied"]
      API --> UI["Dashboard"]
    end
```

## Release identity

A release is bound to all three values:

1. canonical `releaseId` such as `mail-mcp@1.0.0`;
2. `sha256:` artifact digest of exact reviewed bytes;
3. `0x` bytes32 hash of the canonical MCP tool surface.

Admission requires all three. Mutable names and valid publisher signatures are insufficient.

## State ownership

| Component | Owns |
|---|---|
| Scanner | findings, sandbox observations, evidence hash |
| API/SQLite | requests, scans, pending operations, query projection |
| Validators | independent EIP-712 signing keys and decisions |
| ReleaseRegistry | public release hashes, votes, terminal status |
| Indexer/Reconciler | deterministic projection recovery from chain truth |
| Gateway | final pre-spawn admission enforcement |
| Dashboard | read-only LIVE or explicitly labelled REPLAY presentation |

## Status machine

- New release: `UNVERIFIED`
- First `FAIL`: `QUARANTINED`
- Two `PASS` votes: `VERIFIED`
- Two `FAIL` votes: `REVOKED`
- `REVOKED` is terminal for that release ID.

Timeout, unavailable chain truth, an unknown response, and either hash mismatch all result in `BLOCK`.

## Trust boundaries

- Scanner submissions require a dedicated bearer token and are revalidated against shared JSON Schemas. The Backend stamps their source as `LIVE`.
- Validator private keys never enter the API. Signer recovery, validator membership, nonce, deadline, evidence binding, and one-vote-per-release are enforced across API and contract.
- Raw evidence stays off-chain. Only fixed-size hashes, votes, status, and events are placed on-chain.
- The Gateway uses `spawn` with `shell: false`, a command allowlist, and checks admission before creating the child process.
- Dashboard secrets and Backend tokens remain server-side.

## Runtime modes

- `LIVE`: calls the Backend and fails closed on invalid or unavailable status.
- `REPLAY`: consumes committed, explicitly labelled evidence for an offline presentation.
- `MOCK`: deterministic component tests only.
- `LOCAL_DEMO` ledger: Backend mirrors the contract state machine in SQLite.
- `EVM` ledger: Backend reads and writes a deployed `ReleaseRegistry` through an RPC deadline.

The default Compose demo uses `LOCAL_DEMO` for a stable one-command presentation and also starts a local EVM node for contract exploration. Contract integration itself is covered by Ganache tests and can be enabled in Backend EVM mode with a deployed address.
