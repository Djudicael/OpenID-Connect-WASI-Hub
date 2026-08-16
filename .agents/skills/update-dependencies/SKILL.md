---
name: update-dependencies
description: Safely discover, update, and validate Rust Cargo and npm frontend dependencies in the OpenID Connect WASI Hub. Use for dependency bumps, Rust toolchain or MSRV upgrades, Cargo.lock or package-lock.json refreshes, wasi-pg-client upgrades, npm audit follow-up, and compatibility checks across native and wasm32-wasip2 targets.
---

# Update dependencies

## Inspect before editing

1. Read `AGENTS.md`, the root `Cargo.toml`, `rust-toolchain.toml`, and `front/admin/package.json`.
2. Check `git status --short`. Preserve unrelated and untracked user work.
3. Query authoritative registries for current versions. Use `cargo info <crate>` and `npm outdated` or `npm view <package> version`; do not guess versions.
4. Distinguish compatible lockfile refreshes from manifest changes that cross a semver-major boundary. Do not introduce unrelated breaking upgrades unless the request includes them.

## Update Rust

1. Keep shared dependency versions in the root `[workspace.dependencies]` table.
2. Keep `[workspace.package].rust-version` consistent with the pinned channel in `rust-toolchain.toml`. Confirm every selected crate supports that Rust version.
3. Edit manifests deliberately, then regenerate `Cargo.lock` with Cargo. Never hand-edit the lockfile.
4. Preserve WASI Preview 2 constraints: pure-Rust crypto, no filesystem, process spawning, background threads, or native-only transports in WASM dependency paths.
5. Review `cargo update` output for duplicate major versions, unexpected native dependencies, and feature changes.

## Update the admin frontend

1. Work in `front/admin/` and update direct versions with npm so `package.json` and `package-lock.json` stay synchronized.
2. Keep the frontend on native Web Components and `lit-html`; do not introduce a framework.
3. Run `npm outdated` again, then `npm audit`. Report unresolved advisories and avoid force-fixing unrelated breaking changes.

## Validate

Run Rust validation in WSL, not Windows PowerShell. Convert the repository path with `wslpath` when needed.

1. Run `cargo test --workspace` in WSL.
2. Run `cargo build -p openid-connect-wasi --target wasm32-wasip2 --release` in WSL. Do not add native-only crates to the WASM build.
3. In `front/admin/`, run `npm run build` and the relevant Playwright tests. If browsers or external services are unavailable, state exactly what was not run.
4. Inspect `git diff --check`, dependency manifest diffs, and `git status --short` before reporting completion.

Summarize direct version changes, lockfile refreshes, validation results, and any remaining advisories or incompatibilities.
