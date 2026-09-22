# Database

The API uses Node's built-in SQLite driver for zero-setup local demos. The
production-shaped PostgreSQL schema is in `migrations/001_initial.sql` and
contains the same entities and constraints.

Set `DATABASE_PATH` to persist the local SQLite database. It defaults to
`:memory:` during tests and `./mcpshield.db` when the API server starts.

The `/v1` control-plane schema is loaded by `apps/api/src/control-store.ts` for both
SQLite and PostgreSQL. Migration `011_chain_retry_budget.sql` adds only outbox retry
columns: existing actions keep their state, payload, transaction hash and signed bytes;
unmeasured historical attempts are not invented (`attempts = 0`, timestamps null).
The first new worker claim starts the bounded recovery budget. SQLite applies this
extension transactionally; PostgreSQL also records its checksum in the existing
migration ledger. Reopening either database does not reset the budget.

Before deployment, stop writers and take a tested database backup. The rollback plan
is to stop the new worker and roll forward with a corrected bounded worker, or restore
the pre-upgrade backup in an isolated recovery database and reconcile every transaction
submitted since that backup before resuming writes. Do not drop columns/delete DLQ
rows or restore an old snapshot over a live signer: those steps can lose signed
transaction/nonce history. Older application code can read the additive columns, but
older workers lack the retry limits and must not resume chain writes after rollback.

Portable upgrade/reopen check: `node --import tsx --test tests/api/control-plane.test.ts`.
Queue fault checks: `node --import tsx --test tests/api/chain-outbox.test.ts`.
PostgreSQL and Linux/Docker integration results must be recorded separately; skipped
environment-dependent tests are not migration/native PASS evidence.
