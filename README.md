# OpenID Connect WASI Hub

A production-grade, multi-tenant OpenID Connect / OAuth2 identity provider built in Rust with first-class **WASI Preview 2** support.

## Features

- **OIDC Core** — Authorization Code + PKCE, Client Credentials, Refresh Token, ID Tokens (RS256 / EdDSA)
- **Multi-Tenancy** — Per-realm users, clients, sessions, scopes, and branded login pages
- **WASI Preview 2** — Runs as a WASM component via `wasmtime serve` with no filesystem access
- **Admin Console** — Native Web Components management UI (no React/Vue/Angular)
- **Security** — Argon2id password hashing, HMAC-protected session cookies, brute-force protection, CSRF tokens
- **PostgreSQL** — All state persisted in PostgreSQL via `wasi-pg-client`

## Quick Start

### Prerequisites

- Rust 1.85+ with `wasm32-wasip2` target
- Podman (for PostgreSQL container)
- wasmtime ≥ 20 (for running the WASM component)
- Node.js 20+ (for frontend dev server)

```bash
# Add WASM target
rustup target add wasm32-wasip2

# Install wasmtime
curl https://wasmtime.dev/install.sh -sSf | bash
```

### 1. Native Development

```bash
# Start everything: PostgreSQL + native backend + frontend + proxy
cargo run -p oidc-dev -- start

# Open http://localhost:8080 (proxy port)
# Admin login: admin@example.com / Admin123
```

### 2. WASM Development

```bash
# Start everything: PostgreSQL + WASM build + wasmtime serve
cargo run -p oidc-wasm-dev -- start

# Open http://localhost:<port> (auto-assigned)
# Run smoke tests against the WASM server
cargo run -p oidc-wasm-dev -- test
```

### 3. Production Build

```bash
# Native binary
cargo build --release -p openid-connect-wasi

# WASM component
cargo build --release -p openid-connect-wasi --target wasm32-wasip2
```

## Project Structure

| Path | Description |
|------|-------------|
| `crates/oidc-core/` | Pure domain logic. No I/O. No framework deps. |
| `crates/oidc-repository/` | PostgreSQL via `pg_client` (WASM) or `tokio-postgres` (native). |
| `crates/oidc-oidc/` | OIDC/OAuth2 endpoints (Axum). |
| `crates/oidc-apikey/` | API key service + Axum extractor. |
| `crates/openid-connect-wasi/` | Server binary. Dual entry: `#[wstd_axum::http_server]` for WASM, `#[tokio::main]` for native. |
| `crates/oidc-dev/` | Native dev orchestrator (DB + backend + frontend + proxy). |
| `crates/oidc-wasm-dev/` | WASM dev orchestrator (DB + `wasmtime serve`). |
| `front/admin/` | Management UI. Native Web Components + `lit-html`. Built with `esbuild`. |
| `tests/integration/` | Integration tests against real PostgreSQL + HTTP server. |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `OIDC_DATABASE_URL` | `postgresql://localhost/oidc_hub` | PostgreSQL connection string |
| `OIDC_SERVER_BIND_ADDRESS` | `0.0.0.0` | HTTP bind address |
| `OIDC_SERVER_PORT` | `8080` | HTTP server port |
| `OIDC_ISSUER` | `http://localhost:8080` | Base URL for OIDC issuer |
| `OIDC_ENCRYPTION_KEY` | *(required)* | 32-byte hex key for session cookie HMAC |
| `OIDC_CORS_ORIGINS` | *(none)* | Comma-separated allowed CORS origins |

## API Overview

### OIDC Protocol Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /.well-known/openid-configuration` | Discovery document |
| `GET /oidc/jwks` | JSON Web Key Set |
| `GET /oidc/authorize` | Authorization endpoint (with PKCE) |
| `POST /oidc/token` | Token endpoint |
| `GET /oidc/userinfo` | UserInfo endpoint |
| `POST /oidc/introspect` | Token introspection |
| `POST /oidc/revoke` | Token revocation |
| `GET /oidc/logout` | RP-initiated logout |

### Per-Realm Endpoints (Keycloak-compatible)

| Endpoint | Description |
|----------|-------------|
| `GET /realms/{realm}/.well-known/openid-configuration` | Realm-scoped discovery |
| `GET /realms/{realm}/protocol/openid-connect/auth` | Realm-scoped authorize |
| `POST /realms/{realm}/protocol/openid-connect/token` | Realm-scoped token |
| `GET /realms/{realm}/login` | Branded HTML login page |
| `POST /realms/{realm}/login` | Realm-scoped JSON login |

### Admin API

| Endpoint | Auth |
|----------|------|
| `GET /api/stats` | Admin JWT or API key |
| `CRUD /api/realms` | Admin JWT or API key |
| `CRUD /api/users` | Admin JWT or API key |
| `CRUD /api/clients` | Admin JWT or API key |
| `CRUD /api/scopes` | Admin JWT or API key |
| `GET /api/sessions` | Admin JWT or API key |
| `GET /api/audit/events` | Admin JWT or API key |

## Authentication

The server accepts **two** authentication methods on protected admin endpoints:

1. **Bearer Token** — OIDC access token with `admin` scope in the `Authorization: Bearer <token>` header
2. **API Key** — `X-API-Key: <key>` or `Authorization: Bearer <api_key>` header

## Testing

```bash
# Unit tests (native only, no DB needed)
cargo test --workspace --exclude integration-tests

# Integration tests (requires Podman for PostgreSQL container)
cargo test -p integration-tests -- --test-threads=1

# WASM build check
cargo build -p openid-connect-wasi --target wasm32-wasip2 --release
```

## Security Notes

- **Session cookies** are HMAC-SHA256 protected (`session_id.hmac_hex`). Tampered cookies are rejected.
- **CSRF protection** uses a double-submit cookie pattern (`oidc_csrf_token` cookie + `X-CSRF-Token` header).
- **Passwords** are hashed with Argon2id (pure Rust, WASM-compatible).
- **Tokens** use RS256 (RSA) and EdDSA (Ed25519) for signing. Keys are auto-generated on first startup.
- **Brute-force protection** locks accounts after 5 failed login attempts within a short window.
- **No filesystem access** in WASM mode — all configuration and theming lives in PostgreSQL JSONB columns.

## License

MIT OR Apache-2.0
