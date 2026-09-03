# MCPShield Security Policy

## Demo safety boundary

MCPShield is a defensive hackathon prototype. The malicious MCP fixture uses only synthetic data and a loopback or isolated Docker sink.

- Do not publish the malicious fixture to npm or another public registry.
- Do not point the exfiltration sink at an external host.
- Do not use real credentials, customer data, wallet seeds, or API keys in fixtures.
- Do not run untrusted third-party packages in local-process sandbox mode.
- Use Docker mode with an internal network, read-only mounts, dropped capabilities, resource limits, and `no-new-privileges` for behavior tests.

## Supported scope

The MVP protects exact local stdio MCP artifacts whose bytes and tool surface can be pinned. It does not prove the implementation of a remote MCP server that an operator can change after attestation.

## Reporting a vulnerability

Do not open a public issue containing exploit details or secrets. Send the maintainers:

- affected commit and component;
- reproduction steps using synthetic data;
- expected and observed security boundary;
- impact and suggested mitigation;
- whether any secret or third-party system was exposed.

Maintainers should acknowledge a report before publishing details, reproduce it in the isolated demo environment, prepare a fix and regression test, rotate any affected demo credentials, and then publish a concise advisory.

## Secret handling

- `.env` files and database files are ignored by Git.
- Admin, scanner, validator, relayer, and RPC credentials must be distinct.
- Validator private keys never enter the Backend API process.
- Only a hash of evidence is written on-chain; raw evidence remains off-chain.
- Deterministic Ganache keys are local-demo keys and must never be funded or reused.

## Security invariants

1. A release is identified by exact artifact and tool-surface hashes.
2. Only a valid configured validator signature can count toward quorum.
3. A validator can vote at most once per release.
4. Expired, replayed, high-s, or wrong-domain attestations are rejected.
5. `REVOKED` is terminal for a release ID.
6. Admission fails closed for unavailable state, mismatched hashes, or non-verified status.
7. A process is spawned only after admission returns `ALLOW` and `VERIFIED`.
