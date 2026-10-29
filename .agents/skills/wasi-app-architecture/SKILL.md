---
name: wasi-app-architecture
description: Architecture of the OpenID Connect WASI Hub — Rust crates compiled to WASI 0.3 (P3 async) components on the wasm32-wasip2 target, PostgreSQL through wasi-pg-client, and a lit-html admin UI served from its own WASI component. Use when adding a crate, deciding where code belongs, adding a feature end to end, choosing a library, or reviewing a change for structure. Start here; it routes to the specialised wasi-* skills.
---

# OpenID Connect WASI Hub architecture

Goal: code that is **maintainable and readable by a person**. Choose the boring,
explicit option. Prefer small, flat modules. Avoid clever generics.

## Non-negotiable rules

1. **The primary target is `wasm32-wasip2`. Native is for development and tests.**
   `openid-connect-wasi` and `oidc-admin-wasi` compile on both targets. Native
   code exists only for `cargo run`, tests, and tooling.
2. **Library choices are fixed** (table below). Do not add an alternative
   (`sqlx`, `tokio-postgres`, `wstd`, `reqwest` on wasm, Lit, React, …) without
   an explicit, documented decision.
3. **Dependencies point inward:**
   `openid-connect-wasi → oidc-oidc / oidc-apikey → oidc-repository → oidc-core`.
   `oidc-core` has no I/O and no framework dependencies.
4. **Versions live in the root `[workspace.dependencies]`.** Crates write
   `dep = { workspace = true }` and add only features.
5. **Platform differences use `cfg`, never runtime checks:**
   `#[cfg(target_arch = "wasm32")]` / `#[cfg(not(target_arch = "wasm32"))]`
   and target-specific dependency tables.
6. **No filesystem, process spawning, background threads, or "work after the
   response" in a WASI component.** A component handles a request and returns.
   State that must survive a request lives in PostgreSQL.
7. **Pure-Rust crypto only** (`argon2`, `sha2`, `rsa`, `ed25519-dalek`,
   `aes-gcm`, `getrandom` 0.4, `rustls` only where necessary). Never link native
   TLS into a component; outbound HTTPS goes through the host's `wasi:http`.
8. **Never return secrets or internal errors to clients.** Log details with
   `tracing`; return a stable, generic message (OAuth error codes on protocol
   endpoints).

## Fixed library choices

| Concern | WASI (wasm32-wasip2) | Native (dev/tests) |
|---|---|---|
| HTTP server | `axum` 0.8 (`default-features = false`) + `wasip3::exports::http::handler::Guest`, bridged by `oidc-wasi-http::handle` | `axum` + `tokio` (`server::starter::run_tcp`) |
| Async runtime | component-model P3 async executor (`wasip3` 0.8), `futures-concurrency` for races/timeouts | `tokio` |
| Outbound HTTP | `oidc_wasi_http::send` / `read_body` | `reqwest` (rustls, no default features) |
| PostgreSQL | `wasi-pg-client` latest (`0.2.1`, P3 async sockets) | `wasi-pg-client` + `tokio-transport` |
| Errors | `oidc_core::OidcError` (`thiserror`), `anyhow` only in binaries/tooling | same |
| Serialization | `serde`, `serde_json`, `serde_urlencoded` | same |
| IDs / time | `uuid` (v4/v7), `chrono` | same |
| Logging | `tracing` + `tracing-subscriber` (env-filter, json) | same |
| Async traits | `async-trait` | same |
| Test containers | — | `rustainers` (Podman) |
| Frontend | native Custom Elements + **`lit-html`** (not Lit), `esbuild` | — |
| Frontend e2e | — | Playwright |

## Workspace

```text
openid_connect_wasi/
├── Cargo.toml                  # workspace, [workspace.dependencies], profiles
├── rust-toolchain.toml         # pinned channel + wasm32-wasip2 target
├── .cargo/config.toml          # wasm32-wasip2 runner with P3 flags
├── crates/
│   ├── oidc-core/              # models, traits (ports), OidcError, pure utils
│   ├── oidc-repository/        # PostgreSQL repositories, Connection, with_transaction!, mapper
│   ├── oidc-oidc/              # OIDC/OAuth2/SAML endpoints, flows, tokens, federation
│   ├── oidc-apikey/            # API key service, hashing, Axum extractor
│   ├── openid-connect-wasi/    # Hub component: AppState, routers, middleware, composition root
│   ├── oidc-admin-wasi/        # component serving the embedded front/admin build
│   ├── oidc-wasi-http/         # wasm-only P3 HTTP adapters (Axum <-> wasip3, outbound send)
│   ├── oidc-migrate/           # native migration runner
│   ├── oidc-dev/               # native local stack (native binaries)
│   └── oidc-wasm-dev/          # native local stack (WASI components + proxy), P3 runtime tests
├── tests/integration/          # native integration tests (crate `integration-tests`)
├── migrations/postgresql/      # V<n>__<description>.sql
├── front/admin/                # admin UI (see wasi-frontend)
├── deploy/                     # proxy cookbook, platform manifests
└── scripts/                    # release packaging, deploy, backup
```

Read [workspace layout](references/workspace-layout.md) for each crate's
responsibilities and allowed dependencies. Read
[toolchain and Cargo](references/cargo-and-toolchain.md) before editing a
manifest, `rust-toolchain.toml`, or `.cargo/config.toml`.

## Which skill to use

| Task | Skill |
|---|---|
| HTTP routes, handlers, middleware, auth, config, composition root | `wasi-backend-api` |
| Tables, queries, transactions, migrations | `wasi-postgres` |
| Adding S3-compatible object storage (not used yet) | `wasi-object-storage` |
| Admin UI pages, components, routing, API calls | `wasi-frontend` |
| Serving the built admin UI from `oidc-admin-wasi` | `wasi-frontend-packaging` |
| Tests, harness, verification commands, CI | `wasi-testing` |
| `oidc-dev` / `oidc-wasm-dev` local environments | `wasi-dev-stack` |

## Adding a feature end to end

Work from the inside out. Each step compiles before the next one:

1. **oidc-core**: add the model in `models/`, and any new trait or
   `OidcError` variant.
2. **migration**: add `migrations/postgresql/V<next>__<what>.sql`.
3. **oidc-repository**: add `repositories/<thing>_repo.rs` with methods
   taking `conn: &mut Connection`.
4. **oidc-oidc / oidc-apikey**: protocol logic or service code against core
   models and repositories.
5. **openid-connect-wasi**: add the router module (`router/` or
   `router/admin/`), register it in `server/starter.rs`.
6. **front/admin**: add a service function, then a page/component, then the
   route.
7. **verify** with the `wasi-testing` checklist, including the wasm32 build.
8. **docs**: follow `update-project-docs`.

## Deployment model

Two deployables, each a `cdylib` component: `openid_connect_wasi.wasm` (Hub)
and `oidc_admin_wasi.wasm` (admin UI), behind one reverse proxy. Read
[deployment](references/deployment.md) before changing how they are built,
packaged, or configured.

## Review checklist

- Does `oidc-core` still compile without I/O crates (`wasi-pg-client`, `axum`)?
- Is every new dependency declared in `[workspace.dependencies]`, and is it
  wasm-safe or gated to native?
- Does `cargo build -p openid-connect-wasi --target wasm32-wasip2 --release`
  still succeed?
- Are SQL statements parameterised (`$1`, `$2`)? Are user inputs validated at
  the router boundary?
- Are error responses generic, with details logged?
- Do new frontend files follow the lit-html component pattern with no new
  framework?
