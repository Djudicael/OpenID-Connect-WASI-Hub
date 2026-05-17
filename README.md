# OpenID Connect WASI Hub

A multi-tenant OpenID Connect / OAuth2 identity provider built in Rust with first-class **WASI Preview 2** support and an explicit focus on production hardening.

## Features

- **OIDC Core** — Authorization Code + PKCE, Client Credentials, Refresh Token, ID Tokens (RS256 / EdDSA)
- **Multi-Tenancy** — Per-realm users, clients, sessions, scopes, and branded login pages
- **WASI Preview 2** — Runs as a WASM component via `wasmtime serve` with no filesystem access
- **Admin Console** — Native Web Components management UI (no React/Vue/Angular), primarily tested behind a same-origin proxy deployment
- **Security** — Argon2id password hashing, HMAC-protected session cookies, brute-force protection, CSRF tokens
- **PostgreSQL** — All state persisted in PostgreSQL via `wasi-pg-client`

## Quick Start

### `.env` setup for dev / E2E

The repository now includes:

- `.env.template` — tracked template you can copy/share
- `.env` — ignored local file for your machine

Both `oidc-dev` and `oidc-wasm-dev` load `.env` automatically via `dotenv`, so you do not need to export the variables manually every time.

Typical setup:

```bash
cp .env.template .env
# edit .env if needed
```

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

# Open the proxy URL printed by oidc-dev
# Admin login defaults to DEFAULT_EMAIL / DEFAULT_PASSWORD from .env
```

### 2. WASM Development

```bash
# Start everything: PostgreSQL + WASM build + wasmtime serve
cargo run -p oidc-wasm-dev -- start

# Open the proxy URL printed by oidc-wasm-dev
# Admin login defaults to DEFAULT_EMAIL / DEFAULT_PASSWORD from .env

# Run smoke tests against the already running WASM server
cargo run -p oidc-wasm-dev -- test

# Or run the full one-shot WASI smoke flow
cargo run -p oidc-wasm-dev -- smoke
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

### Runtime

| Variable | Default | Description |
|----------|---------|-------------|
| `OIDC_DATABASE_URL` | `postgresql://localhost/oidc_hub` | PostgreSQL connection string |
| `OIDC_SERVER_BIND_ADDRESS` | `0.0.0.0` | HTTP bind address |
| `OIDC_SERVER_PORT` | `8080` | HTTP server port |
| `OIDC_ISSUER` | `http://localhost:8080` | Base URL for OIDC issuer |
| `OIDC_ENCRYPTION_KEY` | *(required)* | 64 hex chars / 32-byte key for session cookie HMAC and JWE encryption |
| `OIDC_CORS_ORIGINS` | *(none)* | Comma-separated allowed CORS origins. This only affects backend CORS responses; it does not by itself make the admin UI cross-origin-ready. |
| `OIDC_RATE_LIMIT_MODE` | `local` | `local` = in-process safety-net limiter, `proxy` / `upstream` = rely on gateway/CDN/global rate limiting, `off` = disable app-local limiting |
| `OIDC_RATE_LIMIT_MAX` | `100` | Max requests per in-process rate-limit window when `OIDC_RATE_LIMIT_MODE=local` |
| `OIDC_RATE_LIMIT_WINDOW_SECS` | `60` | Window size in seconds for the in-process limiter |
| `OIDC_TRUST_PROXY_HEADERS` | `false` | Trust `Forwarded` / `X-Forwarded-For` / `X-Real-IP` only when running behind a proxy that strips and rewrites them |
| `OIDC_SIGNING_KEY` | *(auto-generated)* | RSA private key in PKCS#1 PEM format (global fallback; per-realm keys preferred in production) |
| `OIDC_SIGNING_KID` | `key-1` | Key ID for the global RSA signing key |
| `OIDC_ED25519_KEY` | *(auto-generated)* | Ed25519 private key in PKCS#8 PEM format (global fallback; per-realm keys preferred in production) |
| `OIDC_ED25519_KID` | `ed-key-1` | Key ID for the global Ed25519 signing key |

### Dev / E2E

| Variable | Default | Description |
|----------|---------|-------------|
| `DEFAULT_EMAIL` | `admin@example.com` | Seeded admin email used by `oidc-dev`, `oidc-wasm-dev`, and Playwright E2E helpers |
| `DEFAULT_PASSWORD` | `Admin123` | Seeded admin password used by `oidc-dev`, `oidc-wasm-dev`, and Playwright E2E helpers |
| `PLAYWRIGHT_BASE_URL` | `http://localhost:3000` | Base URL used by Playwright when you run tests directly; `oidc-dev e2e` and `oidc-wasm-dev e2e` set this automatically from the running proxy |

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

### Per-Realm JWKS (Keycloak-compatible)

| Endpoint | Auth Required | Description |
|----------|---------------|-------------|
| `GET /realms/{realm}/protocol/openid-connect/certs` | **No** | Realm-specific public signing keys (RSA + Ed25519). Each realm has its own isolated keypair. Tokens from `realm-a` will **fail** signature verification against `realm-b`'s certs. |

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

## Deployment Posture

### Recommended browser-facing deployment

The primary supported browser deployment model today is:

- **one browser origin** for the admin UI and OIDC/browser-facing routes
- a reverse proxy or gateway in front of the hub
- the proxy serves or fronts the admin UI and forwards `/api`, `/oidc`, `/.well-known`, `/health`, and `/realms/*` to the backend

This matches the current frontend/runtime assumptions:

- frontend OIDC authority uses relative `/oidc`
- browser admin requests use `credentials: 'same-origin'`
- the frontend CSP is same-origin by default
- CSRF handling is designed around same-origin browser/admin traffic

### Separate-origin frontend/API deployments

Separate-origin hosting is **not the primary tested posture** today. If you host the admin UI on a different origin from the API, you must review and test at least:

- frontend OIDC authority / API base configuration
- CSP `connect-src`
- CORS policy (`OIDC_CORS_ORIGINS`)
- CSRF and cookie behavior through the chosen proxy/origin setup

### Production rate limiting

The built-in rate limiter is a **per-instance, in-memory safety net**. For real multi-instance or edge deployments, the recommended production control is a **gateway/CDN/shared upstream rate limiter**.

Suggested production approach:

- enforce the real rate limit at the gateway/CDN/load balancer
- run the app with `OIDC_RATE_LIMIT_MODE=proxy` when that upstream layer is the source of truth
- only enable `OIDC_TRUST_PROXY_HEADERS=true` behind a trusted first-hop proxy that strips and rebuilds forwarding headers

## Testing

```bash
# Unit tests (native only, no DB needed)
cargo test --workspace --exclude integration-tests

# Integration tests (requires Podman for PostgreSQL container)
cargo test -p integration-tests -- --test-threads=1

# WASM build check
cargo build -p openid-connect-wasi --target wasm32-wasip2 --release
```

### Browser E2E via the dev orchestrators

You can run Playwright against either the native proxy (`oidc-dev`) or the WASM proxy (`oidc-wasm-dev`).

#### Native stack

Start the native dev stack in one terminal:

```bash
cargo run -p oidc-dev -- start
```

Then run Playwright in another terminal:

```bash
# Run the whole Playwright suite using the proxy URL discovered by oidc-dev
cargo run -p oidc-dev -- e2e

# Chromium only
cargo run -p oidc-dev -- e2e --project=chromium

# Single spec file
cargo run -p oidc-dev -- e2e front/admin/e2e/login.spec.js --project=chromium
```

#### WASM stack

Start the WASM dev stack in one terminal:

```bash
cargo run -p oidc-wasm-dev -- start
```

Then run Playwright in another terminal:

```bash
# Run the whole Playwright suite using the proxy URL discovered by oidc-wasm-dev
cargo run -p oidc-wasm-dev -- e2e

# Chromium only
cargo run -p oidc-wasm-dev -- e2e --project=chromium

# Single spec file
cargo run -p oidc-wasm-dev -- e2e front/admin/e2e/login.spec.js --project=chromium
```

Both orchestrators automatically inject:

- `PLAYWRIGHT_BASE_URL`
- `DEFAULT_EMAIL`
- `DEFAULT_PASSWORD`

from their running runtime state file.

### Direct Playwright commands

If you want to run Playwright directly instead of through `oidc-dev`:

```bash
# One-time browser install
npm --prefix front/admin run e2e:install

# Run directly against a chosen base URL
PLAYWRIGHT_BASE_URL=http://localhost:3000 \
DEFAULT_EMAIL=admin@example.com \
DEFAULT_PASSWORD=Admin123 \
npm --prefix front/admin run e2e:chromium
```

This is especially useful when running against a manually started proxy or any custom target where you want to bypass the orchestrator-level `e2e` command and set `PLAYWRIGHT_BASE_URL` yourself.

## Production Deployment

### WASM Runtime (`wasmtime serve`)

When running as a WASI Preview 2 component, **every HTTP request may instantiate a fresh WASM component** (depending on `--max-instance-reuse-count`). If signing keys are randomly generated at startup, tokens issued by instance *N* will fail verification on instance *N+1* because the keys differ.

This deployment mode is production-appropriate only when all instances share deterministic key/config material and when abuse controls such as rate limiting are enforced at the gateway/CDN or another shared upstream layer.

**You must provide deterministic signing keys via environment variables:**

```bash
# Generate keys once and store them in your secrets manager
openssl genrsa -out rsa.pem 2048
openssl genpkey -algorithm Ed25519 -out ed25519.pem

# Export for the WASM runtime
export OIDC_SIGNING_KEY="$(cat rsa.pem)"
export OIDC_SIGNING_KID="key-1"
export OIDC_ED25519_KEY="$(cat ed25519.pem)"
export OIDC_ED25519_KID="ed-key-1"
```

Then start `wasmtime serve` with the required WASI worlds enabled:

```bash
wasmtime serve \
  -S cli=y \
  -S inherit-env=y \
  -S inherit-network=y \
  -S tcp=y \
  -S allow-ip-name-lookup=y \
  --env OIDC_DATABASE_URL="postgresql://..." \
  --env OIDC_SIGNING_KEY="$OIDC_SIGNING_KEY" \
  --env OIDC_ED25519_KEY="$OIDC_ED25519_KEY" \
  --env OIDC_ENCRYPTION_KEY="<64-hex-chars>" \
  target/wasm32-wasip2/release/openid_connect_wasi.wasm
```

### Per-Realm Signing Keys (Recommended for Multi-Tenant)

For **enterprise multi-tenancy**, each realm should have its own isolated RSA + Ed25519 keypair. This provides **cryptographic isolation**: a compromised `realm-a` key does not affect `realm-b`, and an API gateway can reject cross-realm tokens at the signature layer.

**How it works:**
- When a realm is created (via `POST /api/realms`), the hub auto-generates a unique keypair and stores it in the `realm_signing_keys` table.
- Tokens issued for that realm are signed with the realm's private keys.
- The `iss` claim in the JWT becomes `https://hub.example.com/realms/{realm}`.
- The public keys are served at `/realms/{realm}/protocol/openid-connect/certs`.

**Gateway validation:**
```nginx
# Example: Nginx JWT validation for a downstream portfolio app
auth_jwt "Portfolio App";
auth_jwt_key_request https://hub.example.com/realms/portfolio/protocol/openid-connect/certs;
```

If per-realm keys are **not** set for a realm, the hub falls back to the global `OIDC_SIGNING_KEY` / `OIDC_ED25519_KEY` for backward compatibility.

### Native Binary

The native binary (`cargo build --release -p openid-connect-wasi`) runs as a single long-lived process, so random key generation at startup is safe. However, for high-availability deployments with multiple replicas, you should still share the same signing keys across all instances so tokens remain valid after load-balancer routing.

## Multi-Tenant Architecture

Realms (tenants) are fully isolated:
- **Users** — per-realm user directories with independent email namespaces
- **Clients** — OAuth2/OIDC clients scoped to a single realm
- **Sessions** — login sessions tied to a realm
- **Scopes** — realm-specific permission definitions
- **API Keys** — realm-scoped admin keys
- **Signing Keys** — each realm can have its own RSA + Ed25519 keypair for cryptographic isolation
- **Branding** — per-realm login page theming (`login_title`, `logo_url`, `primary_color`, `bg_color`)

## Security Notes

- **Session cookies** are HMAC-SHA256 protected (`session_id.hmac_hex`). Tampered cookies are rejected.
- **CSRF protection** uses a double-submit cookie pattern (`oidc_csrf_token` cookie + `X-CSRF-Token` header).
- **Passwords** are hashed with Argon2id (pure Rust, WASM-compatible).
- **Tokens** use RS256 (RSA) and EdDSA (Ed25519) for signing. Global keys are auto-generated on first startup; per-realm keys are auto-generated when a realm is created.
- **Brute-force protection** locks accounts after 5 failed login attempts within a short window.
- **Built-in rate limiting** is local/in-memory unless you intentionally place the app in `proxy` mode and rely on upstream shared enforcement.
- **Proxy headers** are ignored by default. Only enable `OIDC_TRUST_PROXY_HEADERS=true` behind a trusted proxy that strips and rewrites forwarding headers.
- **No filesystem access** in WASM mode — all configuration, theming, and signing keys live in PostgreSQL.
- **Key isolation** — per-realm signing keys prevent cross-tenant token forgery at the cryptographic layer.

## License

MIT OR Apache-2.0
