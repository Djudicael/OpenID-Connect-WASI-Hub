# Backend Implementation Plan

Inspired by `djmxcreation-backend-wasi` crate structure and WASI P2 patterns.

---

## 1. Crate Breakdown

### `crates/oidc-core/` — Domain & Traits
**Responsibility**: All business models, traits, and pure logic. Zero I/O, zero framework dependencies.

```
crates/oidc-core/
├── Cargo.toml
└── src/
    ├── lib.rs
    ├── models/
    │   ├── mod.rs
    │   ├── user.rs
    │   ├── realm.rs
    │   ├── client.rs
    │   ├── session.rs
    │   └── api_key.rs
    ├── traits/
    │   ├── mod.rs
    │   ├── repository.rs
    │   ├── hasher.rs
    │   ├── token_service.rs
    │   └── clock.rs
    ├── errors.rs
    └── utils/
        ├── mod.rs
        ├── id.rs          # UUID v7 generation
        └── time.rs        # Time helpers (mockable via Clock trait)
```

**Key Types**:
- `User`, `Realm`, `Client`, `Session`, `ApiKey`
- `Repository<T>` trait: async CRUD operations
- `TokenService` trait: issue/verify JWTs and opaque tokens
- `Hasher` trait: password hashing abstraction (Argon2id impl)
- `Clock` trait: mockable time for deterministic tests

**Validation Criteria**:
- [ ] `cargo test -p oidc-core` passes with 100% branch coverage on models
- [ ] All models implement `Serialize` + `Deserialize` + `Debug` + `Clone`
- [ ] UUID v7 used for all primary keys (time-sortable, no DB sequence contention)
- [ ] No `std::time::SystemTime::now()` directly; always via `Clock` trait

---

### `crates/oidc-repository/` — PostgreSQL Implementation
**Responsibility**: All SQL queries, connection management, migrations runner interface. Uses `pg_client`.

```
crates/oidc-repository/
├── Cargo.toml
└── src/
    ├── lib.rs
    ├── connection.rs         # Transport abstraction (native vs WASI)
    ├── pool.rs               # Connection pool wrapper
    ├── migrations.rs         # Migration runner (native only; WASM uses pre-migrated DB)
    ├── repositories/
    │   ├── mod.rs
    │   ├── user_repo.rs
    │   ├── realm_repo.rs
    │   ├── client_repo.rs
    │   ├── session_repo.rs
    │   └── api_key_repo.rs
        └── queries/
        ├── mod.rs
        ├── user.sql
        ├── realm.sql
        ├── client.sql
        ├── session.sql
        └── api_key.sql
```

**Key Design Points**:
- `Connection` struct wraps `wasi_pg_client::Connection` on WASM and `tokio_postgres::Client` on native (via `tokio-transport` feature of `pg_client` if available, else a thin compat layer).
- All queries use **parameterized statements** (`$1, $2`) — zero string interpolation.
- `Pool` uses `wasi_pg_pool` on WASM; `deadpool-postgres` on native.
- Migrations run natively via CLI tool (`oidc-migrate`) or in init container.

**Cargo.toml**:
```toml
[dependencies]
oidc-core = { path = "../oidc-core" }
wasi-pg-client = { git = "https://github.com/Djudicael/pg_client", package = "wasi-pg-client" }
wasi-pg-pool = { git = "https://github.com/Djudicael/pg_client", package = "wasi-pg-pool", optional = true }
serde = { workspace = true }
thiserror = { workspace = true }
tracing = { workspace = true }

[target.'cfg(not(target_arch = "wasm32"))'.dependencies]
tokio-postgres = "0.7"
deadpool-postgres = "0.14"

[features]
default = ["pool"]
pool = ["dep:wasi-pg-pool"]
```

**Validation Criteria**:
- [ ] `cargo test -p oidc-repository --features tokio-transport` passes (native integration tests)
- [ ] `cargo build -p oidc-repository --target wasm32-wasip2` succeeds
- [ ] All repositories tested against real PostgreSQL in CI
- [ ] Connection pool acquire timeout ≤ 5s
- [ ] Automatic reconnection on transient `PgError::Broken`

---

### `crates/oidc-oidc/` — OpenID Connect Protocol
**Responsibility**: OAuth2 / OIDC endpoint handlers, token issuance, validation, discovery.

```
crates/oidc-oidc/
├── Cargo.toml
└── src/
    ├── lib.rs
    ├── endpoints/
    │   ├── mod.rs
    │   ├── authorize.rs      # GET /oidc/authorize
    │   ├── token.rs          # POST /oidc/token
    │   ├── userinfo.rs       # GET /oidc/userinfo
    │   ├── introspect.rs     # POST /oidc/introspect
    │   ├── revoke.rs         # POST /oidc/revoke
    │   ├── discovery.rs      # GET /.well-known/openid-configuration
    │   ├── jwks.rs           # GET /oidc/jwks
    │   └── registration.rs   # POST /oidc/register (dynamic client reg)
    ├── flows/
    │   ├── mod.rs
    │   ├── authorization_code.rs
    │   ├── client_credentials.rs
    │   ├── refresh_token.rs
    │   └── hybrid.rs
    ├── tokens/
    │   ├── mod.rs
    │   ├── id_token.rs       # JWT ID Token builder
    │   ├── access_token.rs   # Opaque or JWT
    │   └── refresh_token.rs
    ├── validation.rs         # Request validation helpers
    └── errors.rs             # OIDC-specific error responses
```

**Supported Flows**:
1. Authorization Code + PKCE (mandatory)
2. Client Credentials
3. Refresh Token
4. Hybrid (optional, phase 2)

**Token Formats**:
- ID Token: JWT, signed RS256 or Ed25519
- Access Token: JWT (self-contained) or opaque (reference to DB session)
- Refresh Token: Opaque, hashed in DB

**Validation Criteria**:
- [ ] Authorization Code flow passes conformance tests (https://www.certification.openid.net/)
- [ ] PKCE enforced for public clients
- [ ] Token expiry configurable (default access=15min, refresh=7days, id=1hour)
- [ ] JWKS endpoint exposes public keys only
- [ ] All errors return OAuth2 JSON error format (`application/json`)

---

### `crates/oidc-apikey/` — API Key Management
**Responsibility**: API key CRUD, authentication middleware, rate-limit metadata.

```
crates/oidc-apikey/
├── Cargo.toml
└── src/
    ├── lib.rs
    ├── models.rs             # ApiKey, ApiKeyScope, ApiKeyUsage
    ├── service.rs            # Generation, rotation, revocation
    ├── auth.rs               # Middleware / extractor for Axum
    ├── hashing.rs            # HMAC-SHA256 prefix + bcrypt/argon comparison
    └── endpoints/
        ├── mod.rs
        ├── create.rs
        ├── list.rs
        ├── revoke.rs
        └── rotate.rs
```

**Key Design**:
- Raw key format: `oidc_<prefix>_<random>` (e.g., `oidc_prod_abc123...`)
- Storage: Only HMAC-SHA256 hash of the random part is stored.
- Prefix search: First 8 chars stored in plain for UI display and quick lookup.
- Scopes: Granular scopes per key (e.g., `users:read`, `realms:write`).
- Rotation: New key generated; old key has 24h grace period.

**Validation Criteria**:
- [ ] Raw key displayed only once at creation
- [ ] Key verification ≤ 10ms (argon2id params tuned)
- [ ] Revoked keys rejected immediately (no caching delay)
- [ ] Scoped authorization enforced at endpoint level
- [ ] Usage metrics stored (last_used_at, request_count)

---

### `crates/openid-connect-wasi/` — Server Binary
**Responsibility**: Axum router assembly, server startup, native + WASM entry points.

```
crates/openid-connect-wasi/
├── Cargo.toml
└── src/
    ├── lib.rs
    ├── router/
    │   ├── mod.rs            # Assemble all sub-routers
    │   ├── oidc_router.rs    # /oidc/*
    │   ├── apikey_router.rs  # /api/keys/*
    │   ├── admin_router.rs   # /admin/* (static file serving)
    │   └── health_router.rs  # /health, /metrics
    ├── server/
    │   ├── mod.rs
    │   └── starter.rs        # Native TcpListener / WASI http_server
    ├── middleware/
    │   ├── mod.rs
    │   ├── auth.rs           # Session & API key extraction
    │   ├── cors.rs           # CORS layer
    │   └── logging.rs        # tracing tower layer
    ├── state.rs              # AppState (db pool, config, services)
    └── error.rs              # Global error handler → JSON
```

**Entry Points**:
```rust
// lib.rs
pub fn app_router(state: AppState) -> Router {
    server::starter::build_router(state)
}

#[cfg(target_arch = "wasm32")]
#[wstd_axum::http_server]
fn main() -> Router {
    let state = AppState::from_env_wasi();
    app_router(state)
}

#[cfg(not(target_arch = "wasm32"))]
#[tokio::main]
async fn main() {
    let state = AppState::from_env_native().await;
    server::starter::run_tcp(app_router(state)).await;
}
```

**Cargo.toml**:
```toml
[package]
name = "openid-connect-wasi"
edition = "2024"

[lib]
name = "openid_connect_wasi"
path = "src/lib.rs"
crate-type = ["cdylib", "rlib"]

[dependencies]
oidc-core = { path = "../oidc-core" }
oidc-repository = { path = "../oidc-repository" }
oidc-oidc = { path = "../oidc-oidc" }
oidc-apikey = { path = "../oidc-apikey" }
axum = { version = "0.8", default-features = false, features = ["json", "matched-path", "original-uri", "query", "tower-log", "tracing"] }
serde = { workspace = true }
serde_json = { workspace = true }
tracing = { workspace = true }
tracing-subscriber = { workspace = true }
thiserror = { workspace = true }
anyhow = { workspace = true }
uuid = { workspace = true }

[target.'cfg(target_arch = "wasm32")'.dependencies]
wstd = "0.6"
wstd-axum = "0.6"
wasi = { version = "0.13", features = ["std"] }
getrandom = { version = "0.4", features = ["wasi"] }

[dev-dependencies]
axum-test = { workspace = true }
```

**Validation Criteria**:
- [ ] `cargo build --target wasm32-wasip2` produces `.wasm` artifact
- [ ] `cargo test` runs full native integration test suite
- [ ] Router responds to `/health` with 200 OK on both native and WASM
- [ ] Graceful shutdown on SIGTERM (native) and WASI `stdin` close (WASM)
- [ ] Structured JSON logging in both modes

---

## 2. Shared Workspace `Cargo.toml`

```toml
[workspace]
resolver = "2"
members = [
    "crates/oidc-core",
    "crates/oidc-repository",
    "crates/oidc-oidc",
    "crates/oidc-apikey",
    "crates/openid-connect-wasi",
    "tests/integration",
]

[workspace.package]
version = "0.1.0"
edition = "2024"
rust-version = "1.81"
license = "MIT OR Apache-2.0"

[workspace.dependencies]
# Async / WASI
wstd = "0.6"
wstd-axum = "0.6"
wasi = { version = "0.13", features = ["std"] }

# Web
axum = { version = "0.8", default-features = false, features = ["json", "matched-path", "original-uri", "query", "tower-log", "tracing"] }
tower = { version = "0.5", default-features = false }

# Serialization
serde = { version = "1", features = ["derive"] }
serde_json = "1"

# Database (pg_client)
wasi-pg-client = { git = "https://github.com/Djudicael/pg_client", package = "wasi-pg-client" }
wasi-pg-pool = { git = "https://github.com/Djudicael/pg_client", package = "wasi-pg-pool" }

# Crypto
getrandom = { version = "0.4", features = ["wasi"] }
rustls = { version = "0.23", default-features = false, features = ["std", "tls12"] }
webpki-roots = "0.26"

# Utils
uuid = { version = "1", features = ["v4", "serde"] }
thiserror = "2"
anyhow = "1"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter", "json"] }

# Dev
tokio = { version = "1", features = ["rt", "macros", "net"] }
axum-test = "0.8"
```

---

## 3. Code Quality Gates

| Gate | Tool | Command |
|------|------|---------|
| Lint | clippy | `cargo clippy --all-targets --all-features -- -D warnings` |
| Format | rustfmt | `cargo fmt -- --check` |
| Audit | cargo-audit | `cargo audit` |
| Test (native) | cargo test | `cargo test --workspace` |
| Test (WASM) | wasmtime | `cargo build --target wasm32-wasip2 && wasmtime run ...` |
| Coverage | cargo-llvm-cov | `cargo llvm-cov --workspace --lcov` |
| Docs | cargo doc | `cargo doc --workspace --no-deps` |

---

## 4. Cross-Cutting Concerns

### Error Handling
- `oidc-core::Error` is the domain error enum.
- Each crate maps its errors to `oidc-core::Error` via `thiserror`.
- `openid-connect-wasi` maps `oidc-core::Error` to HTTP responses using `IntoResponse`.

### Tracing
- Every request gets a `trace_id` (UUID v7).
- Spans: `request`, `db_query`, `token_issue`.
- In WASM, logs go to stderr; runtime captures and forwards.

### Configuration
- `AppState` holds all shared dependencies (pool, config, services).
- Config loaded once at startup; immutable after.

---

## 5. Checklist Summary

- [ ] `oidc-core` crate created with models + traits
- [ ] `oidc-repository` crate created with pg_client integration
- [ ] `oidc-oidc` crate created with all OIDC endpoints
- [ ] `oidc-apikey` crate created with middleware
- [ ] `openid-connect-wasi` binary crate with dual entry points
- [ ] Workspace `Cargo.toml` configured
- [ ] Native tests pass (`cargo test`)
- [ ] WASM build succeeds (`cargo build --target wasm32-wasip2`)
- [ ] Health endpoint responds on both native and WASM
- [ ] CI pipeline runs lint + format + audit + test + WASM build
