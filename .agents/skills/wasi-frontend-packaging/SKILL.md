---
name: wasi-frontend-packaging
description: Package the built admin UI (front/admin/dist) into the oidc-admin-wasi WASI 0.3 (P3 async) component that serves the static assets with SPA fallback. Use when changing crates/oidc-admin-wasi, its build.rs asset checks, embedded assets, routes, content types, cache/security headers, or the build order between npm and cargo.
---

# Packaging the admin UI as a WASI component

`crates/oidc-admin-wasi` compiles the admin build **into the component** with
`include_str!` / `include_bytes!`. There is no filesystem at runtime, so the
component is a small, immutable web server. The UI calls the Hub over
relative URLs on the same origin; the reverse proxy routes them.

## Crate

```toml
[lib]
name = "oidc_admin_wasi"
crate-type = ["cdylib", "rlib"]

[dependencies]
axum = { workspace = true }

[target.'cfg(target_arch = "wasm32")'.dependencies]
oidc-wasi-http = { workspace = true }
wasip3 = { workspace = true }

[target.'cfg(not(target_arch = "wasm32"))'.dependencies]
tokio = { workspace = true, features = ["rt-multi-thread", "net", "signal"] }
axum = { workspace = true, features = ["tokio", "http1"] }
```

## Build order

The crate **fails to build until `front/admin/dist` exists**:

```bash
(cd front/admin && npm ci && npm run build)
cargo build -p oidc-admin-wasi --target wasm32-wasip2 --release
```

`build.rs` lists the required assets (`dist/index.html`, `dist/js/index.js`,
`dist/style/bundle.css`), emits `cargo:rerun-if-changed` for each, and panics
with the npm command when one is missing. When the frontend build produces a
new required file, add it to `REQUIRED_ADMIN_ASSETS` and embed it in
`lib.rs`. CI, `oidc-dev`, and `oidc-wasm-dev` already build the frontend
first; keep it that way.

## Entry points

`src/lib.rs` exports the same router for both targets:

```rust
#[cfg(target_arch = "wasm32")]
wasip3::http::service::export!(HttpServer);

#[cfg(target_arch = "wasm32")]
struct HttpServer;

#[cfg(target_arch = "wasm32")]
impl wasip3::exports::http::handler::Guest for HttpServer {
    async fn handle(
        request: wasip3::http::types::Request,
    ) -> Result<wasip3::http::types::Response, wasip3::http::types::ErrorCode> {
        oidc_wasi_http::handle(app_router(), request).await
    }
}
```

`src/main.rs` is the native server (`OIDC_ADMIN_SERVER_BIND_ADDRESS`,
`OIDC_ADMIN_SERVER_PORT`, default 3001).

## Serving rules (`app_router`)

- `/`, `/index.html`, `/admin`, `/admin/{*path}` → `index.html`.
- `/js/index.js` → the bundle; other `/js/*` → 404.
- `/style/main.css`, `/style/bundle.css`, `/style/bundle.<hash>.css` → the CSS
  bundle; other `/style/*` → 404.
- `/{*path}` → `index.html` only when `is_admin_spa_path` accepts it:
  1. the last segment has **no extension** (deep links such as `/clients/42`
     work after a reload; `/favicon.ico` → 404);
  2. the first segment is **not** a Hub route (`api`, `oidc`, `.well-known`,
     `health`) or an asset prefix (`js`, `style`);
  3. `/realms/{realm}/login|protocol|.well-known` are Hub routes, not SPA.

  A missing Hub route must not return the HTML shell, because that hides
  errors from the frontend. Keep this list in sync with the proxy routes in
  `deploy/proxy-cookbook.md` and with `front/admin/app/core/router.js`.
- Only `GET` routes exist; axum returns 405 for other methods.

## Headers

- `content-type` is explicit per asset (`text/html`, `text/javascript;
  charset=utf-8`, `text/css; charset=utf-8`).
- `cache-control: no-store` on `index.html` (and currently on all assets).
  Hashed CSS (`bundle.<hash>.css`) may move to `public, max-age=31536000,
  immutable`.
- When you touch headers, add `x-content-type-options: nosniff` and a CSP
  that mirrors the `<meta>` CSP in `front/admin/index.html`; keep both in sync
  with `front/admin/dev.js`.

## Tests

Unit tests in `src/lib.rs` cover `is_admin_spa_path` and
`is_admin_stylesheet_path`. Add a case for every new route rule. Verify the
wasm build and, for routing changes, the full stack with
`cargo run -p oidc-wasm-dev -- smoke`.
