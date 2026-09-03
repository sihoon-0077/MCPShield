# Chain indexer

Set `RPC_URL`, `REGISTRY_ADDRESS`, `DEPLOYMENT_BLOCK`, and the same
`DATABASE_PATH` used by the API, then run `npm run start:indexer`.

The indexer backfills from the deployment block in bounded ranges, persists a
checkpoint keyed by chain ID and contract, and deduplicates logs by
`(tx_hash, log_index)` before applying projection changes. Vote logs recover
validator votes and synchronize the validator's current contract nonce.

Only blocks behind `CONFIRMATION_DEPTH` (default 3) are projected. Every
checkpoint stores the block hash. A mismatch rewinds `REORG_REWIND_BLOCKS`
(default 20), removes orphaned votes/events, rebuilds statuses/nonces from
surviving logs, and then replays canonical logs. Event insertion and each
projection update run in one SQLite transaction.
