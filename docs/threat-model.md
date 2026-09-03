# MCPShield MVP Threat Model

## Objective

Prevent an AI agent from starting a known-unverified, quarantined, revoked, or hash-mismatched local stdio MCP release, while preserving auditable evidence and multi-validator decisions.

## Protected assets

- agent-accessible files, credentials, messages, and network authority;
- exact MCP artifact bytes and declared tool surface;
- scanner evidence and evidence hash;
- validator identity, nonce, decision, and signature;
- on-chain release status;
- Gateway admission decision and process boundary.

## Trust boundaries

```text
Untrusted artifact
    -> Scanner/Sandbox boundary
        -> authenticated ScanResult
            -> Backend/DB boundary
                -> signed validator attestation
                    -> public-chain boundary
                        -> Indexer/Admission boundary
                            -> local Gateway/process boundary
```

## Threats and controls

| Threat | Impact | MVP control | Residual risk |
|---|---|---|---|
| Signed malicious update | trusted name/signature hides behavior change | artifact/tool hashes, version diff, scanner, sandbox | dormant or environment-specific behavior |
| Tool-description poisoning | agent follows hidden instruction | semantic analysis and evidence span | model false negatives and prompt drift |
| Sensitive file read and egress | secret leakage | canary, internal sink, static rule, Docker isolation | local-process mode is not a security sandbox |
| Fake scan submission | evidence pollution | scanner-only credential, body/rate limits, schema validation | scanner credential compromise |
| Validator impersonation | forged quorum | EIP-712 recovery and contract validator set | real validator key compromise |
| Signature replay | duplicate/cross-domain vote | nonce, deadline, chain ID, contract domain, one vote/release | validator set rotation is not production-complete |
| Relayer/API crash or indexer-first receipt | DB-chain split brain or duplicate write | pending operation lease, chain-truth reconciliation, idempotent upsert, WAL busy timeout | SQLite remains a low-throughput demo projection |
| Indexer downtime/reorg | stale admission state | confirmed-block backfill, checkpoint hash, rewind, dedupe | reorg deeper than configured rewind depth |
| RPC outage | unsafe allow or indefinite wait | deadline and fail-closed decision | availability loss |
| Gateway artifact/runtime drift | unreviewed code or hidden tool execution | Gateway-owned snapshot, minimal environment, shared import policy, filesystem permission boundary, JSON-RPC surface guard | host owner can deliberately bypass the wrapper; network containment still requires deployment sandboxing |
| Evidence disclosure | immutable privacy leak | raw evidence off-chain; only hash on-chain | off-chain store access policy remains deployment-specific |

## Abuse cases

1. An attacker submits a malicious 1.0.1 under a familiar package identity.
2. An unauthenticated caller tries to inject a fake LIVE scan.
3. A caller replays a validator's signature on another chain or contract.
4. A relayer submits a valid vote while the indexer is offline.
5. The API crashes after transaction broadcast but before local persistence.
6. A stale Gateway cache receives a revocation during an RPC outage.
7. A user invokes the MCP binary directly without the Gateway.

## Non-goals

- proving that every remote MCP endpoint runs attested code;
- replacing antivirus, package scanning, or smart-contract auditing;
- preventing a machine owner from disabling enforcement;
- claiming Docker provides a perfect malware containment boundary;
- production decentralization from three demo validator keys.
