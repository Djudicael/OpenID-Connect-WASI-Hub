---
name: wasi-backend-api
description: Build or change the OpenID Connect WASI Hub HTTP component (crates/openid-connect-wasi, plus endpoint code in oidc-oidc and oidc-apikey) using axum on the WASI 0.3 (P3 async) wasip3 HTTP handler with a native tokio twin. Use when adding routes, admin endpoints, handlers, middleware, admin/API-key authentication, AppConfig/AppState, error-to-HTTP mapping, health endpoints, or outbound HTTP calls.
---

# Hub HTTP component

Read `wasi-app-architecture` first for crate boundaries. This skill covers
`crates/openid-connect-wasi` and the Axum handlers in `oidc-oidc` and
`oidc-apikey`.

## 1. Dual entry point

`src/lib.rs` builds the router in one place for both targets and exports the
P3 handler on wasm:

```rust
pub fn app_router() -> Router {
    server::starter::build_router()
}

pub fn app_router_with_config(config: state::AppConfig) -> Router {
    server::starter::build_router_with_config(config)
}

#[cfg(target_arch = "wasm32")]
wasip3::http::service::export!(HttpServer);

#[cfg(target_arch = "wasm32")]
struct HttpServer;

#[cfg(target_arch = "wasm32")]
impl wasip3::exports::http::handler::Guest for HttpServer {
    async fn handle(
        request: wasip3::http::types::Request,
    ) -> Result<wasip3::http::types::Response, wasip3::http::types::ErrorCode> {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(/* RUST_LOG or "info" */)
            .try_init();
        oidc_wasi_http::handle(app_router(), request).await
    }
}
```

`oidc-wasi-http::handle` converts the request with `wasip3::http_compat` and
drives the router with `tower::ServiceExt::oneshot`. HTTP, clocks, and
`wasi-pg-client` sockets all share the P3 async executor. Do **not** use
`wstd` / `wstd-axum`.

`src/main.rs` is the native development server (`#[tokio::main]` →
`server::starter::run_tcp(app_router(), bind, port)`).

Under WASI the host may instantiate the component **per request**. Treat
`build_router()` as cheap: no connection pools and no background tasks.
Caches (for example `RealmTokenServiceCache`) are best-effort only.

## 2. Configuration and state

- `state::AppConfig` holds runtime config. `AppConfig` is loaded from `OIDC_*`
  env vars in `AppState::from_env()`; invalid required values panic at
  startup with a clear message (never echo secret values).
- `state::AppState` holds `Arc<AppConfig>`, the JWT token service, hasher,
  email sender, and `db_config: wasi_pg_client::Config`. It is the router
  state (`Router<AppState>`).
- **Tests use `app_router_with_config(config)`**; never set env vars in tests.
- New variables: name them `OIDC_<NAME>`, add them to `.env.template`, and
  document them (`update-project-docs`).

## 3. Composition root

`server/starter.rs::build_router_with_state` merges every sub-router
(`router::oidc`, `apikey`, `health`, `observability`,
`organization_authorization`, `admin`), applies `.with_state(state)`, then the
global layers. Register new routers there.

## 4. Routers and handlers

- Protocol endpoints live in `oidc-oidc/src/endpoints/`, wired by
  `router/oidc.rs` (global `/oidc/...` and per-realm
  `/realms/{realm}/protocol/openid-connect/...`).
- Admin endpoints: one file per feature in `router/admin/<feature>.rs`,
  registered in `router/admin/mod.rs` under `/api/<resource>` (`/api/realms`,
  `/api/clients`, `/api/users`, …).
- Use axum 0.8 path syntax: `{id}` and `{*rest}`.

Admin handler shape (see `router/admin/clients.rs`):

```rust
pub async fn get(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    auth: AdminAuth,
) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) {
        return r;
    }
    let mut conn = match connect(&state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    match ClientRepo.find_by_id(&mut conn, id).await {
        Ok(Some(c)) => Json(json!({ "id": c.id.to_string(), /* … */ })).into_response(),
        Ok(None) => not_found(),
        Err(e) => {
            tracing::error!(error = %e, "client lookup failed");
            internal_error()
        }
    }
}
```

Rules:

- Keep handlers thin: extract, authorize, validate, call the repository or
  service, map the result.
- Authorize every admin handler with `AdminAuth` plus the realm/organization
  scope helpers (`admin_or_forbidden`, `realm_or_forbidden`, …). Never trust a
  realm ID from the body without checking it against `auth`.
- Use the shared response helpers in `router/admin/mod.rs` (`not_found`,
  `bad_request`, `conflict`, `internal_error`) so the error shape stays
  `{"error": "..."}`. List endpoints return `{"items": [...], "total": n}`.
- Validate input at the boundary (lengths, URLs, enums, page size ≤ 100).
- Body limits: global `DefaultBodyLimit::max(1 MiB)`; override per route only
  when needed.

## 5. Errors to HTTP

- Domain and repository code return `oidc_core::OidcError`.
- Protocol endpoints map it with `oidc_oidc::errors::from_oidc_error` to an
  OAuth error body (`error`, `error_description`) and the matching status.
- `error::AppError` wraps `OidcError` for handlers that use `?`.
- 5xx responses are generic; log the details with `tracing::error!`. Never put
  SQL errors, tokens, or secrets in a response.

## 6. Middleware stack

Applied in `build_router_with_state`, inside out:

1. Per-router: `csrf::csrf_middleware` on browser/admin routers (`admin`,
   `apikey`); requests carrying `x-api-key` skip CSRF.
2. `DefaultBodyLimit`.
3. `cors::cors_layer()`.
4. `security_headers::security_headers_middleware`.
5. `rate_limit::rate_limit_middleware` (in-memory per instance; the proxy is
   the real limiter in `proxy` mode).
6. `logging::logging_middleware`.
7. `observability::instrument` when `OIDC_OBSERVABILITY_TIMING=1`.

Authentication is an extractor (`AdminAuth`, API-key extractor from
`oidc-apikey`), not a global layer, so public protocol routes stay public.

## 7. Health

- `GET /health` → status + version (no I/O).
- `GET /health/live` → always ok.
- `GET /health/ready` → opens a DB connection and runs `SELECT 1` within a
  timeout; 503 on failure.
- Log with structured fields: `tracing::info!(client_id = %id, "created")`.
  Never log tokens, passwords, keys, or connection strings.

## 8. Outbound HTTP

Federation, social login, back-channel logout, CIBA notifications, and email
call other services. Write both targets side by side:

```rust
#[cfg(not(target_arch = "wasm32"))]
async fn fetch(url: &str) -> Result<Vec<u8>, OidcError> { /* reqwest with timeout */ }

#[cfg(target_arch = "wasm32")]
async fn fetch(url: &str) -> Result<Vec<u8>, OidcError> {
    use futures_concurrency::future::Race;
    let request = oidc_wasi_http::Request::get(url)
        .body(oidc_wasi_http::Body::empty())
        .map_err(|e| OidcError::Internal(e.to_string()))?;
    let call = async {
        let response = oidc_wasi_http::send(request)
            .await
            .map_err(|e| OidcError::Internal(format!("upstream request failed: {e:?}")))?;
        if !response.status().is_success() {
            return Err(OidcError::Internal("upstream failed".into()));
        }
        Ok(oidc_wasi_http::read_body(response).await
            .map_err(|e| OidcError::Internal(e.to_string()))?.to_vec())
    };
    let expired = async {
        wasip3::clocks::monotonic_clock::wait_for(Duration::from_secs(5).as_nanos() as u64).await;
        Err(OidcError::Internal("upstream timed out".into()))
    };
    (call, expired).race().await
}
```

Always set a timeout and a maximum response size (`read_body` caps at
16 MiB; use a smaller cap for metadata documents). Validate outbound URLs
before calling them (HTTPS outside local development). TLS is handled by the
host.

## Done when

- `cargo build -p openid-connect-wasi --target wasm32-wasip2 --release`
  passes.
- An integration test in `tests/integration` exercises the new route through
  `app_router_with_config(...)` (see `wasi-testing`).
- Error paths return the documented shape and log server-side details.
- API docs are updated (`update-project-docs`).
