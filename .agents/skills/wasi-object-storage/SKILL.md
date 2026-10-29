---
name: wasi-object-storage
description: Add S3-compatible object storage (RustFS, MinIO, AWS S3) to the OpenID Connect WASI Hub's WASI 0.3 (P3 async) components using aws-sdk-s3 with a custom connector over oidc-wasi-http. The Hub does not use object storage yet; read this before introducing it (for example realm theme assets or export archives). Covers the storage client, uploads, presigned URLs, bucket provisioning, configuration, and tests. Do not use rust-s3 or reqwest-based clients in WASI code.
---

# Object storage (S3 / RustFS)

The Hub has **no object storage today**; all state is in PostgreSQL. Before
adding it, confirm the data really needs it (large binary assets, archives)
and that PostgreSQL (`bytea`/`JSONB`) is not enough. Document the decision.

## Library choice

Use the official **`aws-sdk-s3`**. On wasm it runs with
`default-features = false`, and HTTP is delegated to the host's `wasi:http`
through a small connector, so no native TLS is linked. `rust-s3` and
`reqwest`-based clients are not allowed in WASI code.

```toml
# root Cargo.toml
aws-sdk-s3 = { version = "1", default-features = false }
aws-smithy-runtime-api = { version = "1", features = ["client"] }

# crate Cargo.toml
[target.'cfg(not(target_arch = "wasm32"))'.dependencies]
aws-sdk-s3 = { workspace = true, features = ["default", "behavior-version-latest"] }

[target.'cfg(target_arch = "wasm32")'.dependencies]
aws-sdk-s3 = { workspace = true }
aws-smithy-runtime-api = { workspace = true }
oidc-wasi-http = { workspace = true }
wasip3 = { workspace = true }
```

Check the latest versions with `cargo info` first.

## Where the code goes

- A trait in `oidc-core/src/traits/` (`ObjectStorage`: `put_object`,
  `presigned_get_url`, `delete_object`, …) plus an in-memory fake in
  `traits/mocks.rs`.
- The implementation in a dedicated module (for example
  `oidc-repository/src/storage/`), so `oidc-core` stays free of I/O.
- Wiring in `AppState` (`openid-connect-wasi/src/state.rs`).

## WASI connector

Implement `HttpConnector` / `HttpClient` from `aws-smithy-runtime-api` as
`WasiHttpClient`:

- Convert the Smithy request to `axum::http::Request<oidc_wasi_http::Body>`
  and send it with `oidc_wasi_http::send` (P3 `wasi:http`; it streams the
  body and awaits the response on the same executor as the Hub — no manual
  polling).
- `send` already sets `content-length` when the body size is known. Add
  `content-length: 0` on empty `POST/PUT/PATCH/DELETE` bodies, because RustFS
  otherwise returns 411.
- Map the response back into a Smithy `HttpResponse`.
- Provide an `AsyncSleep` (`WasiSleep`) built on
  `wasip3::clocks::monotonic_clock::wait_for`.

```rust
S3ConfigBuilder::new()
    .behavior_version(BehaviorVersion::latest())
    .sleep_impl(WasiSleep)
    .credentials_provider(Credentials::new(access, secret, None, None, "Static"))
    .region(Region::new(cfg.region))
    .endpoint_url(cfg.endpoint)
    .force_path_style(true)             // required for RustFS/MinIO
    .http_client(WasiHttpClient::new())
```

The native branch uses the same builder without `sleep_impl` and
`http_client`.

## Rules

- Map every SDK error to `OidcError` with context; log `bucket`, `key`, and
  the error, never credentials or presigned URLs.
- Object keys: `<realm_id>/<feature>/<uuid>-<sanitised-name>`. Validate names
  at the API boundary (no `..`, `/`, `\`, or NUL).
- Store the **key**, bucket, and MIME type in PostgreSQL, never a URL.
  Resolve URLs on read.
- Serve objects with short-lived presigned `GET` URLs. They are signed for an
  exact host, so the storage endpoint must be the host browsers reach (HTTPS
  when the Hub is HTTPS). Never rewrite the host after signing.
- Do not stream large files through the component. Keep uploads small (a
  per-route `DefaultBodyLimit`) or use presigned `PUT` / multipart uploads
  directly from the browser.
- Bucket creation, CORS, and lifecycle rules are provisioning work
  (`oidc-dev` / `oidc-wasm-dev`, tests, or deploy scripts). A request handler
  never changes bucket policy.

## Configuration

`OIDC_STORAGE_ENDPOINT`, `OIDC_STORAGE_ACCESS_KEY`, `OIDC_STORAGE_SECRET_KEY`,
`OIDC_STORAGE_REGION` (default `us-east-1`), `OIDC_STORAGE_BUCKET`, added to
`AppConfig`, `.env.template`, and the docs. Credentials are deployment
secrets.

## Testing

- Unit tests use the in-memory fake.
- Integration tests start `docker.io/rustfs/rustfs` once per process from
  `tests/integration/src/harness.rs` (Podman), like the Postgres container.
- The dev CLIs start the same container and provision the bucket.
- The wasm connector is validated by the wasm32 build and an
  `oidc-wasm-dev runtime-test` case.
