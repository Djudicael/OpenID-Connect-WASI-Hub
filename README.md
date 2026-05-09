# OpenID Connect WASI Hub

A production-grade OpenID Connect identity provider with first-class **WASI Preview 2** support, native execution capability, PostgreSQL persistence, and API key management.

## Features

- **WASI P2 First**: Compiles to `wasm32-wasip2` as the primary target.
- **Dual Runtime**: Same code runs natively (dev/tests) and in WASM (production).
- **OIDC Core 1.0**: Authorization Code + PKCE, Client Credentials, Refresh Token flows.
- **API Key Management**: Scoped, revocable, rotatable machine credentials.
- **Zero Frontend Frameworks**: Pure native Web Components admin UI.

## Architecture

See `plan/01-architecture.md` for the full design document.

```
crates/
  oidc-core/          Domain models, traits, pure logic
  oidc-repository/    PostgreSQL implementation (pg_client)
  oidc-oidc/          OpenID Connect & OAuth2 endpoints
  oidc-apikey/        API Key generation, validation, rotation
  openid-connect-wasi/  WASI binary + native server starter
front/
  admin/              Management UI (native Web Components)
```

## Quick Start

### Prerequisites

- Rust 1.81+ with `wasm32-wasip2` target
- PostgreSQL 15+
- wasmtime (for running WASI builds)

### Build (Native)

```bash
cargo build --release
cargo test --workspace
```

### Build (WASI P2)

```bash
cargo build --target wasm32-wasip2 --release
wasmtime run \
  --wasi inherit-network \
  --wasi inherit-env \
  target/wasm32-wasip2/release/openid_connect_wasi.wasm
```

### Admin UI

```bash
cd front/admin
npm install
npm run dev     # http://localhost:3008
npm run build   # Output to dist/
```

## Configuration

Environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `OIDC_DATABASE_URL` | PostgreSQL connection URL | `postgresql://localhost/oidc_hub` |
| `OIDC_SERVER_BIND_ADDRESS` | Server bind address | `0.0.0.0` |
| `OIDC_SERVER_PORT` | Server port | `8080` |
| `OIDC_ENCRYPTION_KEY` | 32-byte base64 encryption key | (required) |


## License

MIT OR Apache-2.0
