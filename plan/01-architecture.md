# OpenID Connect WASI Hub — Master Architecture Document

## 1. Vision & Goals

Build a **production-grade OpenID Connect (OIDC) identity provider** similar to Keycloak, with first-class **WASI Preview 2** support, native execution capability, PostgreSQL persistence via `pg_client`, and a native Web Component management frontend. The system must be deployable in `D:\dev\Wasm-Cloud-Platform` and usable behind a proxy API gateway.

### Key Differentiators
- **WASI P2 First**: Every crate compiles to `wasm32-wasip2` as the primary target.
- **Dual Runtime**: Identical code runs natively (tests, local dev) and in WASM (production).
- **API Key Management**: First-class API keys alongside OIDC sessions.
- **MLS Support**: Messaging Layer Security for end-to-end encrypted group messaging.
- **Zero Frontend Frameworks**: Pure native Web Components, zero React/Vue/Angular.

---

## 2. High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           Proxy API Gateway                                  │
│         (routes /auth/*, /api/*, /admin/* to the WASI component)            │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                     openid-connect-wasi (WASM Component)                     │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │   Router    │  │  OIDC Core  │  │  API Keys   │  │   MLS Management    │ │
│  │   (Axum)    │  │  (OAuth2)   │  │   Service   │  │      Service        │ │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └──────────┬──────────┘ │
│         │                │                │                    │            │
│         └────────────────┴────────────────┴────────────────────┘            │
│                                       │                                     │
│                              ┌────────┴────────┐                            │
│                              │  Domain / Core  │                            │
│                              │    Services     │                            │
│                              └────────┬────────┘                            │
│                                       │                                     │
│                              ┌────────┴────────┐                            │
│                              │   Repository    │                            │
│                              │  (pg_client)    │                            │
│                              └────────┬────────┘                            │
└───────────────────────────────────────┼─────────────────────────────────────┘
                                        │
                                        ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         PostgreSQL Database                                  │
│   (users, realms, clients, sessions, api_keys, mls_groups, key_packages)    │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Workspace Structure

```
openid_connect_wasi/
├── Cargo.toml                     # Workspace manifest
├── rust-toolchain.toml            # Pin to stable + wasm32-wasip2 target
├── .cargo/
│   └── config.toml                # Build profiles for wasm / native
├── crates/
│   ├── oidc-core/                 # Domain models, traits, OIDC protocol logic
│   ├── oidc-repository/           # PostgreSQL repository impl (pg_client)
│   ├── oidc-oidc/                 # OpenID Connect & OAuth2 endpoints
│   ├── oidc-apikey/               # API Key generation, validation, rotation
│   ├── oidc-mls/                  # MLS group/key package/commit handling
│   └── openid-connect-wasi/       # WASI binary + native server starter
├── front/
│   └── admin/                     # Management UI (native Web Components)
├── migrations/
│   └── postgresql/                # SQL schema migrations
├── tests/
│   ├── integration/               # Integration tests (native + WASI)
│   └── e2e/                       # End-to-end tests
├── plan/                          # ← This directory
└── deploy/
    └── wasm-cloud/                # Deployment manifests for Wasm-Cloud-Platform
```

---

## 4. Technology Stack

### Backend (Rust)
| Concern | Native | WASI P2 | Notes |
|---------|--------|---------|-------|
| Async Runtime | `tokio` | `wstd` + `wstd-axum` | `wstd 0.6` provides Send futures |
| Web Framework | `axum` | `axum` (via `wstd-axum`) | Same router code, dual entry points |
| HTTP Server | `tokio::net::TcpListener` | `wstd_axum::http_server` | Conditional compilation on `target_arch` |
| Database | `tokio-postgres` (fallback) | `wasi-pg-client` | `pg_client` with `tokio-transport` feature for native tests |
| TLS | `rustls` | `rustls` + `webpki-roots` | No filesystem access in WASM; embed CA roots |
| Crypto / Random | `ring` | `getrandom` with `wasi` feature | Ensure CSPRNG works in WASM |
| Serialization | `serde` + `serde_json` | same | |
| Logging | `tracing` + `tracing-subscriber` | same | Structured logs |
| Errors | `thiserror` + `anyhow` | same | |
| UUID | `uuid` | same | Enable `v4` feature |
| MLS | `openmls` (pure Rust) | same | Verify WASM compat; fallback to `mls-rs` |

### Frontend
| Concern | Choice |
|---------|--------|
| Language | Vanilla ES2022+ |
| Components | Native Web Components (`HTMLElement`) |
| Templating | `lit-html` (lightweight, no runtime framework) |
| Build | `esbuild` |
| Styling | CSS Custom Properties + Shadow DOM |
| Routing | Custom router element (`<router-outlet>`) |
| State | Lightweight observable store (custom) |

### Database
| Concern | Choice |
|---------|--------|
| Engine | PostgreSQL 15+ |
| Migrations | `refinery` or manual SQL files |
| Connection | `pg_client` (wasi-pg-client) |

---

## 5. Build Matrix

```bash
# Native build (for local dev, tests)
cargo build --release
cargo test

# WASI P2 build (production artifact)
cargo build --target wasm32-wasip2 --release

# Run WASI artifact
wasmtime run \
  --wasi inherit-network \
  --wasi inherit-env \
  target/wasm32-wasip2/release/openid_connect_wasi.wasm
```

---

## 6. Configuration & Environment

The application reads configuration in this priority (highest first):
1. Environment variables (`OIDC_*` prefix)
2. Embedded TOML (compiled into binary for WASM)
3. Sensible defaults

Key settings:
- `OIDC_DATABASE_URL`
- `OIDC_SERVER_BIND_ADDRESS`
- `OIDC_SERVER_PORT`
- `OIDC_REALM_DEFAULT_NAME`
- `OIDC_ENCRYPTION_KEY` (32-byte base64 for cookie/JWE)
- `OIDC_SIGNING_KEY` (RS256 or Ed25519 private key PEM)
- `OIDC_MLS_ENABLED`

---

## 7. Security Model

- **Transport**: TLS 1.3 via `rustls` (WASM uses `webpki-roots`, no filesystem).
- **Password Hashing**: Argon2id (pure Rust `argon2` crate).
- **Token Signing**: RS256 (RSA-PSS) or Ed25519; keys stored in PostgreSQL.
- **Secrets**: API keys use SHA-256 prefix search + HMAC comparison; raw keys shown only once.
- **MLS**: Keys are ephemeral; KeyPackages stored encrypted at rest.

---

## 8. Scalability & Production Constraints (WASI P2)

| Limitation | Mitigation |
|------------|------------|
| Single-threaded | Async event loop; no CPU-bound work on main thread |
| No background tasks | Lazy cleanup (on request), or external cron via gateway |
| No filesystem | Embed certificates, config; use PostgreSQL for all state |
| No process spawn | All tooling (migrations) runs native or in init container |
| Pool maintenance lazy | Eager acquisition on startup; health-check reconnects |

---

## 9. Document Map

| File | Purpose |
|------|---------|
| `01-architecture.md` | This document |
| `02-backend-plan.md` | Detailed backend crate plan |
| `03-database-plan.md` | Schema, migrations, pg_client integration |
| `04-oidc-plan.md` | OIDC/OAuth2 endpoints, flows, token formats |
| `05-apikey-plan.md` | API Key lifecycle, auth middleware, rotation |
| `06-mls-plan.md` | MLS groups, KeyPackages, commits, epoch management |
| `07-frontend-plan.md` | Web Component architecture, build, pages |
| `08-testing-plan.md` | Unit, integration, e2e, security, load tests |
| `09-deployment-plan.md` | Wasm-Cloud-Platform, proxy gateway, CI/CD |
| `10-master-checklist.md` | Complete checklist with validation criteria |

---

## 10. References

- `pg_client`: https://github.com/Djudicael/pg_client
- `djmxcreation_backend` (WASI backend): https://github.com/Djudicael/djmxcreation_backend/tree/main/crates/djmxcreation-backend-wasi
- `djmxcreation_backend` (front): https://github.com/Djudicael/djmxcreation_backend/tree/main/front
- WASI Preview 2: https://github.com/WebAssembly/wasi-preview2
- OpenID Connect Core 1.0: https://openid.net/specs/openid-connect-core-1_0.html
- MLS Protocol (RFC 9420): https://datatracker.ietf.org/doc/html/rfc9420
