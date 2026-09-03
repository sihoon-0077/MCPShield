# ReleaseRegistry

`ReleaseRegistry.sol` records release hashes, one vote per validator, and the
minimum MCPShield status machine. One FAIL quarantines a release and two FAIL
votes revoke it. Two PASS votes verify an unverified release. Revocation is
terminal for a release ID.

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
