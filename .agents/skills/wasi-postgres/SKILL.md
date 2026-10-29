---
name: wasi-postgres
description: Access PostgreSQL from the OpenID Connect WASI Hub (WASI 0.3 / P3 async components and native tests) with the latest wasi-pg-client. Use when writing oidc-repository repositories, SQL queries, row mapping, transactions, Postgres error mapping, or migrations in migrations/postgresql and the oidc-migrate runner. Do not use sqlx, diesel, or tokio-postgres.
---

# PostgreSQL in the Hub

The only database client is **`wasi-pg-client`**
(https://github.com/Djudicael/pg_client). It speaks the Postgres wire protocol
over WASI 0.3 (P3) async sockets on `wasm32-wasip2` and over tokio on native
(`tokio-transport` feature). The same repository code compiles for both
targets.

## Version

Always use the **latest release** (currently `0.2.1`). Check with
`cargo info wasi-pg-client` and bump it through the `update-dependencies`
skill. From 0.2.1 on, the wasm transport needs the P3 async executor, which
the Hub provides through `wasip3::exports::http::handler::Guest` (see
`wasi-backend-api`). Serve components with
`-W component-model-async=y -S p3=y -S tcp=y -S allow-ip-name-lookup=y`.

## Dependencies (`crates/oidc-repository/Cargo.toml`)

```toml
[dependencies]
wasi-pg-client = { workspace = true, features = ["uuid", "chrono", "serde-json"] }

[target.'cfg(not(target_arch = "wasm32"))'.dependencies]
wasi-pg-client = { workspace = true, features = ["tokio-transport", "uuid", "chrono", "serde-json"] }
```

No async runtime crate is needed on wasm. For timeouts there, race the future
against `wasip3::clocks::monotonic_clock::wait_for(nanos)` with
`futures-concurrency` (see `oidc-oidc/src/direct_ldap.rs`); on native use
`tokio::time::timeout`.

## Connection model

**Open one connection per request or unit of work.** A WASI component cannot
keep a pool between requests; pooling belongs outside the component
(PgBouncer). TLS to the database is handled by the network/host layer.

- `AppState.db_config` / `OidcState.db_config` hold a `wasi_pg_client::Config`
  parsed once from `OIDC_DATABASE_URL`.
- Open a connection with `OidcState::connect()` or, in admin handlers,
  `router::admin::connect(&state)`. Both wrap
  `wasi_pg_client::Connection::connect` in `oidc_repository::Connection`.
- Repositories are unit structs (`pub struct ClientRepo;`) whose methods take
  `conn: &mut Connection`, so one connection serves several repositories.

## Queries

- **Always parameterise**: `$1, $2, …`. Never use `format!` to build values
  into SQL. `format!` is acceptable only for constant column lists such as
  `const CLIENT_COLUMNS: &str`.
- Escape `%`, `_`, and `\` in user search text used with `LIKE`/`ILIKE`
  (`escape_like` in `client_repo.rs`).
- Use `RETURNING …` instead of a second `SELECT`.
- Paginate with `LIMIT $n OFFSET $m` and return `(items, total)`. Bound the
  page size at the API boundary (maximum 100).
- Filter soft-deleted rows (`deleted_at IS NULL`) where the table has the
  column.
- Scope every realm-owned query by `realm_id`.

```rust
pub async fn find_by_id(&self, conn: &mut Connection, id: Uuid) -> Result<Option<Client>, OidcError> {
    let sql = &format!("SELECT {CLIENT_COLUMNS} FROM clients WHERE id = $1 AND deleted_at IS NULL");
    let row = conn.query_one_params(sql, &[&id]).await.map_err(mapper::pg_err)?;
    row.map(|r| Self::map_row(&r)).transpose()
}
```

## Transactions

Use `with_transaction!` (`oidc-repository/src/connection.rs`) when several
statements must commit together; it begins, commits on `Ok`, and rolls back on
`Err`:

```rust
let user = with_transaction!(conn, pg_err, {
    let user = UserRepo.find_by_email(conn, realm_id, email).await?;
    // … more statements on the same `conn` …
    Ok(user)
})?;
```

Consuming one-time artefacts (auth codes, refresh tokens, reset tokens, device
codes) must be atomic: a conditional `UPDATE … RETURNING` or a transaction.

## Row mapping

- Map by index with the helpers in `mapper.rs` (`mapper::uuid(row, 0)`,
  `mapper::opt_string`, `mapper::datetime`, `mapper::json_string_vec`, …).
- The `const …_COLUMNS` list sits directly above the repository and its order
  must match `map_row` indices. Update both together.
- Rows map straight into `oidc_core::models` types. Handlers never see `Row`.
- Use `JSONB` for flexible documents (`serde_json::Value`) and typed columns
  for everything you filter or join on.

## Error mapping

`mapper::pg_err(PgError) -> OidcError`:

| Postgres error | `OidcError` |
|---|---|
| unique violation (23505) | `Conflict` → 409 in admin APIs |
| anything else | `Internal` (log at `error`, never expose the message) |

If a caller needs another distinction (foreign key, not null), extend
`pg_err` using `wasi_pg_client::error::sqlstate` codes rather than matching
strings at call sites.

## Migrations

Files: `migrations/postgresql/V<n>__<snake_description>.sql` (for example
`V5__audit_events.sql`). Rules:

- Versions are unique and only increase. **Never edit an applied migration**;
  add a new one with the next free number.
- Make statements idempotent where cheap (`CREATE TABLE IF NOT EXISTS`,
  `ADD COLUMN IF NOT EXISTS`, `CREATE INDEX IF NOT EXISTS`).
- `uuid` primary keys, `timestamptz` timestamps, explicit foreign keys with
  `ON DELETE` behaviour, and an index for every foreign key and filtered
  column.
- Store secrets hashed or encrypted (`AppState::encrypt_sensitive_value`),
  never in clear text.

`crates/oidc-migrate` (native only, `OIDC_DATABASE_URL=... cargo run -p
oidc-migrate`):

- Reads `migrations/postgresql`, parses `V<n>`, rejects duplicate versions,
  and sorts numerically.
- Takes `pg_advisory_lock` with a `lock_timeout` so concurrent runners are
  safe.
- Applies each file with `batch_execute` inside `BEGIN`/`COMMIT` and records
  it in `_migrations(filename)` in the same transaction.

Components **never** migrate at startup. `oidc-dev` / `oidc-wasm-dev` and the
integration harness run the migrations for local and test databases.

## Testing

Repository and database tests live in `tests/integration` (`repo_tests/`,
`db_tests/`) against a real Postgres started once per test process by
`harness.rs` (rustainers + Podman). See `wasi-testing`.
