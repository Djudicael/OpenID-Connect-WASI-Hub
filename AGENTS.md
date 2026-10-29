# AGENTS.md

These instructions apply to every coding agent working in this repository.

## Shared Agent Skills

Repository-local skills live in `.agents/skills/` and are plain Markdown so any coding agent (including Codex, Claude Code, and OpenCode) can use them. `.claude/skills/` contains thin Claude Code discovery adapters that point to the canonical files. Before a matching task, read the complete canonical skill (and its `references/` folder when present) and follow it together with this file. If a skill's trigger description changes, update its Claude adapter too.

| Skill | Use for |
|---|---|
| `.agents/skills/wasi-app-architecture/SKILL.md` | **Start here.** Crate layout, dependency direction, fixed library choices, feature workflow, deployment |
| `.agents/skills/wasi-backend-api/SKILL.md` | `openid-connect-wasi` (+ `oidc-oidc`/`oidc-apikey` handlers): routers, `AppState`, errors, middleware, admin auth, outbound HTTP |
| `.agents/skills/wasi-postgres/SKILL.md` | `wasi-pg-client` repositories in `oidc-repository`, transactions, error mapping, migrations (`oidc-migrate`) |
| `.agents/skills/wasi-object-storage/SKILL.md` | Adding S3/RustFS storage via `aws-sdk-s3` over `oidc-wasi-http` (not used yet) |
| `.agents/skills/wasi-frontend/SKILL.md` | `front/admin`: native Web Components + `lit-html`, esbuild, Playwright |
| `.agents/skills/wasi-frontend-packaging/SKILL.md` | `oidc-admin-wasi`: embedding and serving the built admin UI (SPA fallback) |
| `.agents/skills/wasi-testing/SKILL.md` | Unit tests with in-memory mocks, `tests/integration` (Podman), P3 runtime test, e2e, verification checklist, CI |
| `.agents/skills/wasi-dev-stack/SKILL.md` | `oidc-dev` / `oidc-wasm-dev` local environment CLIs |
| `.agents/skills/update-dependencies/SKILL.md` | Dependency, Rust toolchain, Cargo lockfile, or npm package updates |
| `.agents/skills/update-project-docs/SKILL.md` | Feature, API, configuration, deployment, UI, or security documentation updates |

### WASI runtime in the skills

All `wasi-*` skills describe this repository: components export the **WASI 0.3 (P3) async** handler (`wasip3::exports::http::handler::Guest`) through `oidc-wasi-http`, outbound HTTP uses `oidc_wasi_http::send`, and PostgreSQL uses the latest `wasi-pg-client`. Never add `wstd` / `wstd-axum`. When the code changes one of these patterns, update the matching skill in the same change.

## Project Context

This is the **OpenID Connect WASI Hub** — an identity provider built in Rust with WASI 0.3 asynchronous HTTP and sockets on the stable `wasm32-wasip2` compiler target.

### Build System
- **Primary target**: `wasm32-wasip2` (P2 std with P3 async HTTP and sockets)
- **Dev target**: native (`x86_64` or `aarch64`), only for development and tests
- **Build command (native)**: `cargo build --release`
- **Build command (WASI)**: `cargo build -p openid-connect-wasi --target wasm32-wasip2 --release`
- **Run (WASI)**: `wasmtime serve -W component-model-async=y -S p3=y -S cli=y -S inherit-network=y -S inherit-env=y -S tcp=y -S allow-ip-name-lookup=y target/wasm32-wasip2/release/openid_connect_wasi.wasm` (Wasmtime 48.0.1 or compatible P3 ABI)

### Workspace Layout
- `crates/oidc-core/` — Pure domain logic. No I/O. No framework deps.
- `crates/oidc-repository/` — PostgreSQL via `wasi-pg-client` (P3 sockets on WASM, Tokio transport on native).
- `crates/oidc-oidc/` — OIDC/OAuth2 endpoints (Axum).
- `crates/oidc-apikey/` — API key service + Axum extractor.
- `crates/openid-connect-wasi/` — Server. Async `wasip3::exports::http::handler::Guest` for WASM, `#[tokio::main]` for native.
- `crates/oidc-admin-wasi/` — WASI component serving the built `front/admin` assets.
- `crates/oidc-wasi-http/` — Shared WASI 0.3 HTTP adapters for Axum server/client operations.
- `crates/oidc-migrate/` — SQL migration runner.
- `crates/oidc-dev/`, `crates/oidc-wasm-dev/` — Native-only local environment CLIs (containers, builds, smoke tests).
- `tests/integration/` — Native-only integration tests.
- `front/admin/` — Management UI. Native Web Components + `lit-html`. Built with `esbuild`, tested with Playwright.

### Key Constraints
- **WASI**: No filesystem access, no process spawning, no background threads.
- **Database**: PostgreSQL only. All queries parameterized (`$1`, `$2`). No `sqlx`, `diesel`, or `tokio-postgres`.
- **Crypto**: Pure Rust only (`argon2`, `rustls`, `getrandom` with `wasi` feature).
- **Frontend**: No React/Vue/Angular/Svelte or `LitElement`. Only native `HTMLElement` + `lit-html`.
- **Dependencies**: Keep Rust dependency versions centralised in `[workspace.dependencies]`.
- Preserve unrelated changes, and never replace a lockfile without updating its matching manifest.

### Testing
- Run build, test, format, lint, and dependency commands in **WSL**, not Windows PowerShell. Load `~/.nvm/nvm.sh` before npm commands when nvm is installed.
- Native tests: `cargo test --workspace`
- WASM build check: `cargo build -p openid-connect-wasi --target wasm32-wasip2 --release`
  - Note: `oidc-dev`, `oidc-wasm-dev`, and `tests/integration` are native-only (container/process deps) and must be excluded from WASM builds.
- Follow the verification checklist in `.agents/skills/wasi-testing/SKILL.md` before finishing a change.

### Deployment
- Proxy API gateway (Nginx/Traefik) in front; see `deploy/proxy-cookbook.md`.
- `wasmtime serve` with P3 async enabled for both HTTP components.

### References
- `pg_client`: https://github.com/Djudicael/pg_client
- `djmxcreation_backend` (WASI pattern): https://github.com/Djudicael/djmxcreation_backend/tree/main/crates/djmxcreation-backend-wasi
- `djmxcreation_backend` (front pattern): https://github.com/Djudicael/djmxcreation_backend/tree/main/front
