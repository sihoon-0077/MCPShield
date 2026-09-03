# Chain indexer

Set `RPC_URL`, `REGISTRY_ADDRESS`, `DEPLOYMENT_BLOCK`, and the same
`DATABASE_PATH` used by the API, then run `npm run start:indexer`.

The indexer backfills from the deployment block in bounded ranges, persists a
per-contract checkpoint, and deduplicates logs by `(tx_hash, log_index)` before
polling for new blocks. Restarting it resumes from the last completed range.
