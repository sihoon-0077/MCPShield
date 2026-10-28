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

## Independent baseline selection (scoped 2.1 only)

Use the same `VALIDATOR_SOURCES_PATH` file; no new environment variable or service
is needed. Its optional `baselines` object maps **current prepared release IDs**
to explicit `null` or a selected baseline prepared ID. `sources[]` still maps
original source IDs to operator-owned acquisition locations, not prepared IDs.
The file remains bounded to 512 KiB, 128 sources and 128 baseline entries. IDs
must be lowercase `0x` plus 64 hex characters. A missing map/entry is rejected
for 2.1 rather than treated as null; 2.0 and legacy do not require the map.

Operational order:

1. Prepare the current source with an explicit baseline ID or null through the API.
2. Check the returned immutable runtime binding and derived current prepared ID.
3. Each validator operator pins that current ID → selected baseline ID/null in
   its own sources file and includes both original source acquisition entries.
4. Run the existing single-key command `node --import tsx apps/validator/src/v2.ts`
   (or `--quarantine-only` for independently confirmed critical FAIL).

The map is reread before and after independent scanning and before signing. Only
its checked selected entry enters the private config hash; an API `baselineReleaseId`
or bundle leaf cannot create the independent selection anchor. Both source trees,
provenance, publisher pins and actual image closures are checked. Changing the map,
source or authority invalidates that run. The exact 13-field baseline trust binds
the selected prepared ID separately from its original source ID. No previous
approval, API-advertised VALID/PASS or comparison-only scan can bypass current
evidence and quorum requirements.

The opt-in native 2.1 fullcycle uses three separate operator selection files,
single-key OS processes and local EVM: safe null-baseline PASS reaches approvals
2 then 3; malicious update selects the safe prepared identity, C quarantines,
then A/B produce the two FAIL attestations and both Gateways block. Its AI is a
loopback contract stub, not measured external-provider quality. See the API README
for its opt-in flags; portable synthetic evidence is not proof this native run passed.

## V3 independent validator (ADR-008)

`apps/validator/src/v3.ts` is the validator for `ReleaseRegistryV3`. It does not
sign the operator's report. For one release it:

1. reads the release identity from chain and checks that its **own copy** of the
   artifact resolves to exactly those digests (`ARTIFACT_IDENTITY_MISMATCH` otherwise);
2. scans that copy itself and derives its own verdict: a deterministic non-AI
   HIGH/CRITICAL finding is FAIL; otherwise an AI (non-deterministic) HIGH/CRITICAL
   suspicion or an incomplete scan is ABSTAIN (ADR-002); everything else is PASS;
3. writes its own evidence file (report + validator address + identity) and signs
   the sha256 of that file as `evidenceHash`;
4. with `--quarantine`, sends a direct emergency quarantine from its own key when
   its scan has a deterministic CRITICAL sandbox finding.

Disagreeing with other validators is a normal outcome; V3 records the dissent.
The round window (`VALIDATOR_VALID_FROM`/`VALIDATOR_VALID_UNTIL`) is the one the
operator announced, so honest validators land in the same round. Scope today:
local-source artifacts under the default policy. Prepared and OCI profiles still
use `v2.ts`.

```bash
VALIDATOR_PRIVATE_KEY=... CONTROL_V2_RPC_URLS=https://sepolia.base.org CONTROL_V2_CHAIN_ID=84532 \
CONTROL_V3_REGISTRY_ADDRESS=0x... CONTROL_VALIDATOR_POLICY_HASH=0x... VALIDATOR_RELEASE_ID=0x... \
VALIDATOR_ARTIFACT_DIR=demo/fixtures/mail-mcp-1.0.1 VALIDATOR_BASELINE_DIR=demo/fixtures/mail-mcp-1.0.0 \
VALIDATOR_VALID_FROM=... VALIDATOR_VALID_UNTIL=... VALIDATOR_EVIDENCE_DIR=data/validator-evidence \
node --import tsx apps/validator/src/v3.ts --quarantine
```

`VALIDATOR_RELAYER_PRIVATE_KEY` lets a validator without gas have its signed vote
relayed; the quarantine is always sent by the validator itself.
