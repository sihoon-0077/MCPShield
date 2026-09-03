# Database

The API uses Node's built-in SQLite driver for zero-setup local demos. The
production-shaped PostgreSQL schema is in `migrations/001_initial.sql` and
contains the same entities and constraints.

Set `DATABASE_PATH` to persist the local SQLite database. It defaults to
`:memory:` during tests and `./mcpshield.db` when the API server starts.
