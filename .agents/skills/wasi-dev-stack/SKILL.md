---
name: wasi-dev-stack
description: Run or change the Hub's native local-environment CLIs — oidc-dev (native backend binary + frontend dev server) and oidc-wasm-dev (both WASI 0.3 / P3 components under wasmtime serve) — which start Podman PostgreSQL, run migrations, seed data, build the admin UI and components, expose a same-origin proxy, and run smoke, P3 runtime, and Playwright tests. Use when starting the local stack, or adding a service, command, seed, or check to either CLI.
---

# Local development stacks

Two native-only crates spin up a complete Hub locally. They are tooling, so
they may spawn processes, use Podman, and touch the filesystem; never pull
them into a wasm32 build.

| CLI | Runs | Use for |
|---|---|---|
| `oidc-dev` | native `openid-connect-wasi` binary + `front/admin` dev server | fast backend/UI iteration |
| `oidc-wasm-dev` | `openid_connect_wasi.wasm` + `oidc_admin_wasi.wasm` under `wasmtime serve` | production-like P3 runtime checks |

Run both from the repository root in WSL.

## Commands

`cargo run -p oidc-dev -- <command>`:

| Command | Behaviour |
|---|---|
| `start` | DB + migrations + seed + frontend build + backend + frontend dev server + proxy; Ctrl-C stops everything |
| `db-only` | DB + migrations only |
| `wasm` | DB + the Hub component via wasmtime |
| `stop`, `status`, `logs` | manage / inspect the running stack |
| `test` | smoke tests against the running server |
| `e2e` | Playwright against the running proxy |

`cargo run -p oidc-wasm-dev -- <command>`:

| Command | Behaviour |
|---|---|
| `start` | DB + migrations + seed + frontend build + both wasm builds + two `wasmtime serve` processes + proxy |
| `stop`, `status`, `seed` | manage the stack / reseed |
| `test` | smoke tests against the running stack |
| `smoke` | one shot: start → smoke tests → shutdown |
| `runtime-test [--skip-build]` | verifies P3 HTTP server/client, PostgreSQL sockets, and deadlines in the real components (uses the `oidc-wasi-http` `http-client-smoke` probe; CI runs it) |
| `e2e` | Playwright against the running WASM proxy |

## How a start works

1. **Preflight**: check `podman`, `npm`, and (for WASM) `wasmtime` versions.
   Fail early with an actionable message.
2. **Database**: `postgres:16-alpine` through `rustainers` (Podman), database
   `oidc_hub`. The container is dropped when the CLI exits.
3. **Migrations**: apply `migrations/postgresql` (same rules as
   `oidc-migrate`, see `wasi-postgres`).
4. **Seed**: realm, admin user (`DEFAULT_EMAIL` / `DEFAULT_PASSWORD` from
   `.env`, with dev fallbacks), the `admin-ui` client, and test clients
   (`test-service` / `test-service-secret`). Seeding is idempotent.
5. **Build**: `npm run build` in `front/admin`; for `oidc-wasm-dev`,
   `cargo build --target wasm32-wasip2 --release` for both components.
6. **Run**: native binaries, or `wasmtime serve --addr 127.0.0.1:<port>
   -W component-model-async=y -S p3=y -S cli=y -S inherit-network=y
   -S inherit-env=y -S tcp=y -S allow-ip-name-lookup=y <component>.wasm` with
   the `OIDC_*` env passed explicitly.
7. **Proxy**: a small Node `http-proxy` (installed into a temp directory)
   gives one origin: Hub routes (`/api`, `/oidc`, `/.well-known`, `/health`,
   `/realms/{realm}/{login,protocol,.well-known}`) to the backend, everything
   else to the frontend — the same split as `deploy/proxy-cookbook.md`.
8. **Runtime file**: ports, URLs, and PIDs are written to a JSON file in the
   temp directory (`oidc-hub-dev-runtime.json` /
   `oidc-hub-wasm-dev-runtime.json`) so `status`, `test`, `stop`, and `e2e`
   find the running stack. `PLAYWRIGHT_BASE_URL` points at the proxy.

Ports are picked dynamically from defaults (backend 8080, frontend 3008,
proxy 3000) when they are busy; always read them from the runtime file or the
banner instead of hard-coding them.

## Changing the CLIs

- Keep both CLIs in step: a new required env var, seed, route prefix, or build
  step usually belongs in both, and in the proxy route list.
- Keep commands safe to repeat: seeding is idempotent, and `stop` should
  succeed when nothing runs.
- Never print secrets other than the documented dev credentials.
- Child processes are tracked in the state struct and killed on Ctrl-C/stop;
  do not leave orphaned `wasmtime` or `node` processes.
- Document new commands in the crate header comment and the README
  (`update-project-docs`).

## Done when

- `cargo clippy -p oidc-dev -p oidc-wasm-dev --all-targets -- -D warnings`
  passes.
- `cargo run -p oidc-wasm-dev -- smoke` succeeds for runtime-affecting
  changes, and `runtime-test` for P3 HTTP / database changes.
