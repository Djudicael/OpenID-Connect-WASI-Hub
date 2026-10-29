---
name: wasi-testing
description: Test and verify the OpenID Connect WASI Hub (WASI 0.3 / P3 async components) and its lit-html admin UI. Use when writing unit tests with oidc-core in-memory mocks, integration tests in tests/integration against Podman PostgreSQL via rustainers, P3 runtime checks, Playwright e2e tests in front/admin/e2e, when running the verification checklist before finishing a change, or when editing CI workflows and Dependabot.
---

# Testing and verification

## Environment

- Run Rust and npm commands in **WSL**, not Windows PowerShell. From
  PowerShell, call `wsl.exe --cd <repo path in WSL> bash -lc '<command>'`.
- Load nvm before Node commands when nvm is installed: `source ~/.nvm/nvm.sh`.
- Respect `rust-toolchain.toml`.
- Integration tests use **Podman** through `rustainers`. If Podman is
  unavailable, report it as an environment limitation and keep it separate
  from code failures.

## Test pyramid

| Level | Where | Tools | What |
|---|---|---|---|
| Domain unit | `oidc-core` `#[cfg(test)]` | std | models, validation, utils |
| Crate unit | `#[cfg(test)]` in `oidc-oidc`, `oidc-apikey`, `openid-connect-wasi`, `oidc-repository` | `oidc_core::traits::mocks` (`InMemoryUserRepo`, `MockTokenService`, …), `tokio::test` | flows, token logic, middleware, mapping, `with_transaction!` behaviour |
| Integration | `tests/integration` (crate `integration-tests`) | `harness.rs` + `helpers::app::TestApp`, `reqwest` | real SQL, migrations, full HTTP flows, security |
| P3 runtime | `oidc-wasm-dev runtime-test` | wasmtime + `http-client-smoke` probe | P3 HTTP server/client, PostgreSQL sockets, deadlines inside the real component |
| End to end | `front/admin/e2e/*.spec.js` | Playwright against `oidc-dev` / `oidc-wasm-dev` | admin flows, deep links, documentation screenshots |

## Unit tests

- Prefer the in-memory implementations in `oidc-core/src/traits/mocks.rs` to
  mocking frameworks. Add a new in-memory repo there when a trait gains a
  consumer that needs unit tests.
- Assert side effects (what was stored, revoked, or emitted) as well as
  return values.

## Integration tests (`tests/integration`)

- `harness.rs` starts **one** `postgres:16-alpine` container per test process
  (`tokio::sync::OnceCell`), removes stale containers from earlier runs, and
  migrates a template database `oidc_hub_test`.
- `TestApp::new()` creates an isolated database per app with
  `CREATE DATABASE … WITH TEMPLATE = 'oidc_hub_test'`, builds the app with
  `app_router_with_config(config)`, serves it on a random port, and exposes
  a `reqwest` client plus seed helpers (`seed_user`, `seed_client`,
  `seed_client_with_secret`, `db_conn`, …).
- **Never call `std::env::set_var`** in tests; they run in parallel. Pass
  config through `AppConfig`.
- Signing keys are generated once per process (`test_signing_keys`).
- Put tests in the matching module (`oidc_tests/`, `admin_tests/`,
  `repo_tests/`, `security_tests.rs`, …). Each test creates its own rows with
  fresh UUIDs/emails and never assumes an empty table.
- Assert on status, response shape (`{"error": …}` for admin APIs, OAuth
  `error`/`error_description` for protocol endpoints), and absence of
  internal details.

Run them with `cargo test -p integration-tests` (Podman required).

## Verification checklist (run before reporting done)

```bash
# frontend (when front/admin changed, and before building oidc-admin-wasi)
source ~/.nvm/nvm.sh
(cd front/admin && npm ci && npm run build)

# rust: quick
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace --exclude integration-tests

# locally patched crypto dependencies (separate upstream test lockfiles)
cargo test --locked --manifest-path patches/passkey-auth/Cargo.toml --lib --tests
cargo test --locked --manifest-path patches/saml/Cargo.toml --lib

# wasm32 (P3 components)
cargo build --locked -p openid-connect-wasi -p oidc-admin-wasi --target wasm32-wasip2 --release
cargo clippy --locked -p openid-connect-wasi -p oidc-admin-wasi -p oidc-wasi-http \
  --target wasm32-wasip2 --lib --examples -- -D warnings

# full (Podman)
cargo test --locked -p integration-tests

# P3 runtime (wasmtime 48.0.1, after the wasm builds)
cargo build --locked -p oidc-wasi-http --example http-client-smoke --target wasm32-wasip2 --release
cargo run --locked -p oidc-wasm-dev -- runtime-test --skip-build

# e2e (when UI or admin API changed; stack running)
(cd front/admin && npm run e2e)

# hygiene
git diff --check
git status --short
```

Report the exact commands you ran, which passed, and anything that was not run
and why. Do not weaken assertions to make a test pass.
`scripts/check-coverage.sh` gives a local coverage report.

## CI (`.github/workflows/ci-cd.yml`)

- **security**: `cargo deny --locked check advisories bans licenses sources`.
- **validate**: fmt → `npm ci` + `npm run build` in `front/admin` → strict
  clippy → unit tests (`--exclude integration-tests`) → release wasm builds →
  wasm32 clippy → install pinned Wasmtime 48.0.1 (checksum verified) →
  `oidc-wasm-dev runtime-test --skip-build` against a Postgres service →
  upload `front/admin/dist`.
- Tags run `scripts/package-release.sh`.
- Keep `permissions` minimal and pin action versions. When changing Wasmtime,
  update the version and the checksum together.

Dependabot covers GitHub Actions, Cargo, and `front/admin` npm. Follow
`update-dependencies` for upgrades.
