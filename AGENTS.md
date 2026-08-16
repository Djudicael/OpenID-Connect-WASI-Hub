# AGENTS.md

## Shared Agent Skills

Repository-local skills live in `.agents/skills/` and are plain Markdown so any coding agent (including Codex, Claude Code, and OpenCode) can use them. Before a matching task, read the complete skill instructions and follow them together with this file.

- Dependency, Rust toolchain, Cargo lockfile, or npm package updates: read `.agents/skills/update-dependencies/SKILL.md`.

## Project Context

This is the **OpenID Connect WASI Hub** — a production-grade identity provider (like Keycloak) built in Rust with first-class WASI Preview 2 support.

### Build System
- **Primary target**: `wasm32-wasip2` (WASI Preview 2)
- **Dev target**: native (`x86_64` or `aarch64`)
- **Build command (native)**: `cargo build --release`
- **Build command (WASI)**: `cargo build -p openid-connect-wasi --target wasm32-wasip2 --release`
- **Run (WASI)**: `wasmtime run --wasi inherit-network --wasi inherit-env target/wasm32-wasip2/release/openid_connect_wasi.wasm`

### Workspace Layout
- `crates/oidc-core/` — Pure domain logic. No I/O. No framework deps.
- `crates/oidc-repository/` — PostgreSQL via `pg_client` (WASM) or `tokio-postgres` (native).
- `crates/oidc-oidc/` — OIDC/OAuth2 endpoints (Axum).
- `crates/oidc-apikey/` — API key service + Axum extractor.
- `crates/openid-connect-wasi/` — Server binary. Dual entry: `#[wstd_axum::http_server]` for WASM, `#[tokio::main]` for native.
- `front/admin/` — Management UI. Native Web Components + `lit-html`. Built with `esbuild`.

### Key Constraints
- **WASI P2**: No filesystem access, no process spawning, no background threads.
- **Database**: PostgreSQL only. All queries parameterized (`$1`, `$2`).
- **Crypto**: Pure Rust only (`argon2`, `rustls`, `getrandom` with `wasi` feature).
- **Frontend**: No React/Vue/Angular. Only native `HTMLElement` + `lit-html`.

### Testing
- Run tests in **WSL**, not Windows PowerShell.
- Native tests: `cargo test --workspace`
- WASM build check: `cargo build -p openid-connect-wasi --target wasm32-wasip2 --release`
  - Note: `oidc-dev` and `integration-tests` are native-only (Docker/process deps) and must be excluded from WASM builds.

### Deployment
- Target directory: `D:\dev\Wasm-Cloud-Platform\oidc-hub\`
- Proxy API gateway (Nginx/Traefik) in front.
- `wasmtime serve` or `wasmtime run` for the WASM component.

### References
- `pg_client`: https://github.com/Djudicael/pg_client
- `djmxcreation_backend` (WASI pattern): https://github.com/Djudicael/djmxcreation_backend/tree/main/crates/djmxcreation-backend-wasi
- `djmxcreation_backend` (front pattern): https://github.com/Djudicael/djmxcreation_backend/tree/main/front
