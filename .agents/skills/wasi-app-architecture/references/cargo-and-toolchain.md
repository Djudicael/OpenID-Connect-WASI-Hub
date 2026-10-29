# Cargo, toolchain, and build configuration

## `rust-toolchain.toml`

The channel is pinned (with `wasm32-wasip2`, `rustfmt`, `clippy`,
`llvm-tools-preview`). Keep `[workspace.package].rust-version` consistent with
it, and bump it deliberately through the `update-dependencies` skill. Never
silently build with a different toolchain.

## Root `Cargo.toml`

- Every member is listed in `[workspace] members`.
- Versions live in `[workspace.dependencies]`; workspace crates are declared
  there with `path = "crates/<name>"`.
- WASI runtime entries:

```toml
# Async / WASI (P3 async HTTP, clocks, and sockets on the wasm32-wasip2 target)
wasip3 = { version = "0.8", features = ["http-compat"] }
futures-concurrency = "7"

# Database — always the latest release; 0.2.1+ uses P3 async sockets.
wasi-pg-client = "0.2.1"
```

Before choosing a version, check the registry (`cargo info <crate>`). Never
guess a version. Record each intentional pin with a comment explaining why.
Never add `wstd` / `wstd-axum`: they run a P2 executor that the latest
`wasi-pg-client` cannot use.

## Target-specific dependencies (component crates)

Pattern from `crates/openid-connect-wasi/Cargo.toml`:

```toml
[dependencies]
axum = { workspace = true }
wasi-pg-client = { workspace = true }

[target.'cfg(target_arch = "wasm32")'.dependencies]
oidc-wasi-http = { workspace = true }
wasip3 = { workspace = true }
getrandom = { workspace = true }

[target.'cfg(not(target_arch = "wasm32"))'.dependencies]
tokio = { workspace = true, features = ["rt-multi-thread", "net", "signal"] }
axum = { workspace = true, features = ["tokio", "http1"] }
wasi-pg-client = { workspace = true, features = ["tokio-transport", "uuid", "chrono", "serde-json"] }
reqwest = { workspace = true }
```

Rules:

- `wasi-pg-client` uses its P3 socket transport automatically on
  `wasm32-wasip2`. **Only native builds add `tokio-transport`.** When you
  change its features, update the native and wasm declarations together.
- `oidc-wasi-http` and `wasip3` are wasm-only dependencies.
- Gate tooling crates (`rustainers`, `reqwest`, `tokio` with `process`, `nix`,
  `portpicker`) to native, or keep them in native-only crates.

## `.cargo/config.toml`

```toml
[target.wasm32-wasip2]
# HTTP cdylib components are started explicitly with `wasmtime serve`.
runner = "wasmtime run -W component-model-async=y -S p3=y -S cli=y -S inherit-network=y -S inherit-env=y -S tcp=y -S allow-ip-name-lookup=y"
```

Do not set `build.target`. Native remains the default, so `cargo test` works.
The release profile (`opt-level = 3`, `lto`, `strip`, `codegen-units = 1`,
`panic = "abort"`) also lives in this file.

## Lints and supply chain

- CI runs `cargo clippy --locked --workspace --all-targets -- -D warnings` and
  a wasm32 clippy pass on `openid-connect-wasi`, `oidc-admin-wasi`, and
  `oidc-wasi-http`.
- `deny.toml` (cargo-deny) checks advisories, bans, licenses, and sources.
  Every `ignore` entry carries a `reason`.

## Local patches

Avoid forking crates. If a dependency panics under WASI, first look for a
feature flag or a wasm-friendly alternative. If a patch is unavoidable, use
`[patch.crates-io]` pointing to a crate inside the repository, document the
reason, and list removal conditions.
