# ReleaseRegistry

`ReleaseRegistry.sol` records release hashes, one vote per validator, and the
minimum MCPShield status machine. One FAIL quarantines a release and two FAIL
votes revoke it. Two PASS votes verify an unverified release. Revocation is
terminal for a release ID.

Votes are EIP-712 attestations signed by validators and may be relayed by any
account. The contract recovers the signer and enforces the validator set,
per-validator nonce, deadline, low-s signature, and one vote per release. The
API and validators never share validator private keys.

Run `npm run chain:local` to start a deterministic local Ganache network and
deploy the contract in one command. The printed keys/addresses are for local
demo use only.

For Base Sepolia or another EVM network:

```powershell
$env:RPC_URL='https://...'
$env:DEPLOYER_PRIVATE_KEY='0x...'
$env:VALIDATOR_ADDRESSES='0x...,0x...,0x...'
npm run chain:deploy
```

Do not commit private keys. The contract never stores raw evidence.

## ReleaseRegistryV3 (ADR-008)

`ReleaseRegistryV3.sol` reuses the V2 `ValidatorRegistry` and `PolicyRegistry` and
keeps the V2 read surface (`releases`, `getDecision`, `validators`, `policies`), so
a Gateway only changes the registry address. What changes is the vote:

- A round is (release, policy, validity window, validator set). The report is not
  part of it, so validators that scan independently still count toward one 2-of-3.
- Each validator signs its own `evidenceHash` (EIP-712 domain version `"3"`).
  Every vote, including FAIL/ABSTAIN dissent after a decision, is stored and
  emitted as `VoteRecorded`.
- Two FAIL revoke the release and its bytes. Two PASS approve. Three votes with
  neither quorum are `SPLIT`: the release is not admissible and `ReviewRequired`
  is emitted until validators decide a new round.

Deploy with the V2 script and the `--v3` flag (`node --import tsx
contracts/scripts/deploy-v2.ts --deploy --v3`). The API, validator app and indexer
still write V2; see [ADR-008](../docs/adr-008-independent-evidence-and-dissent.md).
