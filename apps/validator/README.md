# V2 single-key validator

Run `node --import tsx apps/validator/src/v2.ts` with the operator-owned
`VALIDATOR_PRIVATE_KEY`, API/RPC coordinates, policy hash, source catalogue,
prepared-runtime pins and explicit AI settings described in `apps/api/README.md`.
Private keys belong in operator secrets, never command-line arguments or API bodies.

- No flag: independently verify, sign and submit one attestation.
- `--quarantine`: existing demo flow, optionally quarantine a reported FAIL and then attest.
- `--quarantine-only`: independently verify critical FAIL evidence, sign one emergency
  quarantine and confirm its transaction; **do not** submit an attestation afterward.

Quarantine-only requires exactly one key. Combining flags, repeating flags,
unknown flags, `--quarantine-only=true`, and non-boolean programmatic mode values
are rejected. `runValidatorFanout({..., quarantineOnly: true})` uses the same
independent scan, current source/config checks, fresh active validator/nonce/domain,
strict payload reconstruction, signature and confirmed-transaction path. It is
not verify-only or a way to convert PASS/ABSTAIN into authority. API verdicts do
not decide whether this path runs; missing or inconsistent critical evidence rejects.

The opt-in scoped `tests/api/prepared-fullcycle.test.ts` runs A/B PASS, proves
VERIFIED at exactly two approvals, then runs C PASS. For malicious bytes, C first
confirms quarantine, A records the first FAIL, and B's second FAIL makes REVOKED
terminal. All three use separate keys and OS processes for each source. Its three
malicious independent-verification receipts mean **one quarantine plus two
attestations**, not three accepted FAIL attestations after revocation.

Receipts remain private `LOCAL_VERIFICATION_ONLY` records, not on-chain receipts
or proof that signing/submission succeeded. The native test additionally binds
each receipt's address and report roots to the observed child PID, successful CLI
exit and confirmed operation. It uses local EVM, actual Linux Docker and loopback
AI contracts; it makes no external-organization, testnet or production-AI claim.
