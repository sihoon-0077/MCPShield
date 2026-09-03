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
