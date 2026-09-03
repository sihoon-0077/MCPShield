# MCPShield Integration Checklist

## Automated gates

- [x] Clean workspace install with `npm ci`
- [x] Backend TypeScript check and Dashboard production build
- [x] Backend/API/indexer/recovery tests
- [x] Solidity compile and EIP-712/quorum/replay tests
- [x] Security fixture, AI schema, sandbox, redaction, timeout, and submission tests
- [x] Gateway LIVE/MOCK/REPLAY identity and pre-spawn block tests
- [x] Offline replay smoke test
- [x] Ephemeral LIVE Backend end-to-end smoke test
- [x] Security benchmark with sample size and source labels
- [x] Production dependency audit
- [x] Compose structure and security-policy static validation

## P0 demo acceptance

- [x] Safe and malicious signed-update fixtures
- [x] Exact artifact and tool-surface hashes
- [x] Static, AI, and sandbox evidence
- [x] 2-of-3 validator state transition
- [x] Gateway rejects non-verified or mismatched release before spawn
- [x] One-screen dashboard with releases, findings, votes, events, and admissions
- [x] Second Gateway demonstrates shared revocation decision
- [x] Offline fallback script

## External environment checks

- [ ] Build and run the Compose stack on a Docker-capable Linux host
- [ ] Verify Docker sandbox seccomp/network behavior at runtime
- [ ] Deploy and verify `ReleaseRegistry` on Base Sepolia
- [ ] Record contract address, deployment transaction, chain ID 84532, and explorer links
- [ ] Test public demo URL and repository permissions in an incognito browser
- [ ] Capture a 60-second fallback video and a 3-minute submission video
- [ ] Confirm the final proposal is at most 10 pages and contains at most one external link

## Release hygiene

- [x] `.env.example` contains no usable secrets
- [x] Demo keys and tokens are labelled deterministic localhost-only values
- [x] Backend and Gateway fail closed on unavailable trust state
- [x] `SECURITY.md` and threat model exist
- [ ] Choose and add a repository license before making the project public
- [ ] Run the final repository secret scan immediately before publishing
- [ ] Pin the public demo commit and record its checksum
