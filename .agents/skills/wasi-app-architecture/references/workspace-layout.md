# Workspace layout

Each crate's job, what it may depend on, and where code goes.

## `oidc-core` — domain

- `models/`: one file per aggregate (`client.rs`, `user.rs`, `realm.rs`, …).
  Plain structs and enums with `serde` derives. No `Row`, no HTTP types.
- `traits/`: ports used across crates (`Hasher`, `EmailSender`, `Clock`,
  `TokenService`, repository traits) plus `mocks.rs` / `noop_email.rs` for
  tests and defaults.
- `errors.rs`: `OidcError`, the single domain error. Add a variant only when a
  caller must react to it differently (it maps to an OAuth error code or HTTP
  status in `oidc-oidc::errors`).
- `utils/`: pure helpers (IDs, validation, encoding).

Allowed dependencies: `serde`, `serde_json`, `thiserror`, `uuid`, `chrono`,
`async-trait`, pure crypto. **No** `axum`, `wasi-pg-client`, `wasip3`, `tokio`.

## `oidc-repository` — PostgreSQL

- `connection.rs`: the `Connection` wrapper and the `with_transaction!` macro.
- `mapper.rs`: `pg_err` (PgError → `OidcError`) and by-index column helpers.
- `repositories/<thing>_repo.rs`: a unit struct (`pub struct ClientRepo;`)
  whose async methods take `conn: &mut Connection` and return
  `Result<_, OidcError>`.

Depends on `oidc-core` and `wasi-pg-client` (`tokio-transport` on native only).
See `wasi-postgres`.

## `oidc-oidc` — protocol

- `endpoints/`: Axum handlers for authorize, token, userinfo, login, MFA,
  CIBA, SAML, social login, session/logout, …
- `flows/`: grant implementations (authorization code, refresh, device,
  CIBA, password).
- `tokens/`: JWT signing/verification (`JwtTokenService`).
- `state.rs`: `OidcState` (per-request; `connect()` opens a DB connection).
- `errors.rs`: `OidcError` → OAuth/HTTP response mapping.

Depends on `oidc-core`, `oidc-repository`, and `oidc-wasi-http` (wasm only)
for outbound calls.

## `oidc-apikey`

API key models, hashing, service, endpoints, and the Axum extractor
(`ApiKeyVerifierState`). Depends on `oidc-core` and `oidc-repository`.

## `openid-connect-wasi` — the Hub component

```toml
[lib]
crate-type = ["cdylib", "rlib"]   # cdylib = component, rlib = tests and native bin
```

```text
src/
├── lib.rs                # pub mods, app_router(), app_router_with_config(), wasip3 Guest export
├── main.rs               # #[tokio::main] native entry
├── state.rs              # AppConfig (env) + AppState (services, db_config)
├── error.rs              # AppError: OidcError -> Response
├── server/starter.rs     # build_router(), build_router_with_config(), run_tcp()
├── router/               # oidc, apikey, health, observability, organization_authorization, admin/*
├── middleware/           # admin_auth, auth, cors, csrf, logging, observability, rate_limit, security_headers
├── email_sender.rs       # Resend-backed EmailSender
└── dns_verifier.rs
```

Details are in `wasi-backend-api`.

## `oidc-wasi-http`

wasm-only (`#![cfg(target_arch = "wasm32")]`): `handle(router, request)`,
`send(request)`, `read_body(response)`. Every component and every outbound
call on wasm goes through it. The `http-client-smoke` example is the probe
used by `oidc-wasm-dev runtime-test`.

## `oidc-admin-wasi`

Serves `front/admin/dist` from compile-time embedded assets. See
`wasi-frontend-packaging`.

## Native-only crates

- `oidc-migrate`: applies `migrations/postgresql/` (see `wasi-postgres`).
- `oidc-dev`, `oidc-wasm-dev`: local environments (see `wasi-dev-stack`).
- `tests/integration` (`integration-tests`): Podman-backed tests (see
  `wasi-testing`).

Never add these to a wasm32 build.

## Naming quick reference

| Thing | Convention | Example |
|---|---|---|
| Crate | `oidc-<role>` | `oidc-repository` |
| Repository | `<Thing>Repo` in `<thing>_repo.rs` | `ClientRepo` |
| Admin router | `router/admin/<feature>.rs` | `router/admin/clients.rs` |
| Migration | `V<n>__<snake_description>.sql` | `V5__audit_events.sql` |
| Env var | `OIDC_<NAME>` | `OIDC_DATABASE_URL` |
| Frontend page | `<name>-page.js`, tag `<name>-page` | `clients-page.js` |
| Frontend component | `components/ui/<name>.js`, tag `c-<name>` | `c-button` |
