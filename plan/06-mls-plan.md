# Messaging Layer Security (MLS) Plan — CANCELLED

> **Status**: ❌ **CANCELLED** — Will not be implemented.
>
> **Date**: 2025-01-06
>
> **Reason**: No production-grade MLS library supports `wasm32-wasip2` (WASI Preview 2). Both evaluated libraries (`openmls`, `mls-rs`) are browser-WASM only and trap at runtime in Wasmtime.

---

## Why MLS Cannot Be Implemented

### 1. Library Evaluation Results

| Library | Native | `wasm32-wasip2` | Root Cause |
|---------|--------|-----------------|------------|
| `openmls` | ✅ Works | ❌ Compile error | Mandatory `rayon` + `js` feature requiring `fluvio-wasm-timer` (browser `Date.now`) |
| `mls-rs` | ✅ Works | ⚠️ Compiles, traps at runtime | `wasm-bindgen` for `MlsTime::now()` + `getrandom` `js` feature (browser `Math.random`) |
| Custom impl | ✅ Works | ✅ Works | Estimated 5,000–30,000 lines of RFC 9420 protocol logic — not viable |

### 2. Technical Blockers

**`openmls`**:
- `rayon` is a **mandatory** dependency (not feature-gated). On WASM it degrades to sequential but the `js` feature is required for compilation.
- `fluvio-wasm-timer` calls JavaScript `Date.now()` — unavailable in Wasmtime.
- `getrandom` with `js` feature calls `Math.random()` via `wasm-bindgen` — unavailable in Wasmtime.

**`mls-rs`**:
- `mls-rs-core/src/time.rs` uses `wasm_bindgen::date_now()` on `target_arch = "wasm32"`.
- `mls-rs` enables `getrandom` `js` feature on WASM targets.
- Both produce imports like `__wbindgen_placeholder__::__wbindgen_describe` that Wasmtime cannot resolve.

### 3. Why Patching Is Not Viable

Patching `mls-rs` to support WASI would require:
1. Forking `mls-rs-core` — replace `wasm_bindgen` time with `std::time::SystemTime` (works on `wasm32-wasip2`)
2. Forking `mls-rs` — remove `getrandom` `js` feature, use default (uses `wasi::random`)
3. Maintaining these forks indefinitely upstream

This is a significant ongoing maintenance burden for a feature that is not core to the identity provider's mission.

### 4. Security Argument Against Stubs

A half-implemented MLS layer (stubs on WASM, real crypto on native) is a **security liability**:
- Operators may deploy to WASM expecting E2EE and receive silent failures.
- The same codebase behaving differently on two targets violates the principle of least surprise.
- MLS is a safety-critical cryptographic protocol — partial implementation is worse than no implementation.

---

## Decision

**MLS is removed from the project entirely.**

- The `oidc-mls` crate has been deleted.
- MLS database tables, migrations, and indexes have been removed.
- MLS models, repositories, endpoints, and routes have been removed.
- MLS dependencies (`mls-rs`, `mls-rs-core`, `mls-rs-crypto-rustcrypto`, `openmls`) have been removed from `Cargo.toml`.
- All documentation references to MLS have been or will be updated.

---

## Future Path (If WASI MLS Becomes Possible)

If a WASI-compatible MLS library emerges, or if `mls-rs`/`openmls` add native WASI Preview 2 support:

1. Re-evaluate library compatibility with `cargo build --target wasm32-wasip2`.
2. Verify runtime functionality with `wasmtime run`.
3. Re-implement using the **API key plan pattern** (full audit, gap analysis, implementation, test harness).

Until then, **end-to-end encrypted messaging is out of scope** for this identity provider.

---

## References

- MLS Protocol (RFC 9420): https://datatracker.ietf.org/doc/html/rfc9420
- `openmls`: https://github.com/openmls/openmls (browser WASM only)
- `mls-rs`: https://github.com/awslabs/mls-rs (browser WASM only)
- WASI Preview 2: https://github.com/WebAssembly/WASI/tree/main/wasip2
