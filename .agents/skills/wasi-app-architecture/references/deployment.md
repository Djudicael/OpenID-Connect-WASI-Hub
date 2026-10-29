# Deployment model

## Artifacts

Two components on the `wasm32-wasip2` target, each exporting the WASI 0.3
(P3) async HTTP handler:

```bash
(cd front/admin && npm ci && npm run build)      # oidc-admin-wasi embeds dist/
cargo build --locked --release --target wasm32-wasip2 -p openid-connect-wasi -p oidc-admin-wasi --lib
# → target/wasm32-wasip2/release/openid_connect_wasi.wasm
# → target/wasm32-wasip2/release/oidc_admin_wasi.wasm
```

`scripts/package-release.sh --version <v>` builds the release bundle used by
CI on tags.

Run one component locally (Wasmtime 48.0.1 or a compatible P3 ABI):

```bash
wasmtime serve -W component-model-async=y -S p3=y -S cli=y -S inherit-network=y \
  -S inherit-env=y -S tcp=y -S allow-ip-name-lookup=y \
  target/wasm32-wasip2/release/openid_connect_wasi.wasm
```

## Topology

A reverse proxy (Nginx/Traefik, see `deploy/proxy-cookbook.md`) fronts both
components on one origin: the Hub serves `/api/`, `/oidc/`, `/.well-known/`,
`/health*`, and `/realms/{realm}/{login,protocol,.well-known}`; everything
else goes to the admin component (SPA shell and assets). Same
origin keeps cookies, CSRF, and the CSP `connect-src 'self'` working.

## Configuration

- The same `.wasm` runs everywhere. Everything environment-specific comes from
  `OIDC_*` environment variables (`OIDC_DATABASE_URL`, `OIDC_ISSUER`,
  `OIDC_ENCRYPTION_KEY`, `OIDC_PAIRWISE_SALT`, `OIDC_RESEND_API_KEY`, …; see
  `.env.template` and `crates/openid-connect-wasi/src/state.rs`).
- Secrets come from the platform's secret store, never from committed files.
  Commit only templates/examples.
- Restrict outbound network access to PostgreSQL and the external services
  actually called (email, social login, federation).

## Rules

- Apply database migrations (`oidc-migrate`) **before** deploying a component
  version that needs them. Components never migrate at startup.
- Keep `scripts/deploy.sh` / `scripts/rollback.sh` and the README deployment
  section in sync when changing artifacts or flags (`update-project-docs`).
- Tests start their own containers through `rustainers`; they never depend on
  a deployed or compose-managed stack.
