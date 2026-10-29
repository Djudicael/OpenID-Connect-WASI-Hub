# Check dependency security before a release

[Documentation home](README.md) · [Operations](operations.md)

Use the repository's pinned Rust toolchain and run the commands from the
repository root in WSL. Cargo.lock and both lockfiles under `patches/` must be
present. Install `cargo-deny` if it is not available; PostgreSQL integration
tests need Podman, and the WASI runtime checks need Wasmtime 48.0.1 and OpenSSL.

## Check the resolved dependencies

```bash
cargo deny --locked check advisories bans licenses sources
cargo tree --locked -i crypto-bigint
```

The checked-in root lockfile resolves `crypto-bigint 0.7.10`. The local
`passkey-auth` and `saml` patches move their elliptic-curve dependencies to the
corrected RustCrypto stack. Their origins, exact changes, licenses and removal
conditions are documented in [patch maintenance](../patches/README.md).

These patches preserve the existing libraries and public application APIs.
They do not introduce database migrations or a passkey re-enrollment procedure.
They are maintained locally until compatible upstream releases replace them;
replacing either library with another implementation would be a separate migration.

If the security command fails, inspect its advisory and dependency chain before
releasing. Refresh dependencies with Cargo and rerun the checks. Do not remove
the patch entries or substitute an advisory exception to clear this failure.

## Account for the existing RSA exception

Passing `cargo deny` means the dependency graph satisfies [deny.toml](../deny.toml),
including its explicit exceptions. It does not mean every dependency is free of
known vulnerabilities. The policy still ignores `RUSTSEC-2023-0071` for `rsa`,
used by the hub's RSA flows. The cryptographic dependency patches do not fix
that separate issue and add no exception for `RUSTSEC-2026-0387`.

Review the RSA exception when updating its dependency chain. The reason for the
exception remains recorded in `deny.toml`.

## Validate a dependency update

Run the reproducible [patch test commands](../patches/README.md#validation),
then the [workspace and WASI checks](../README.md#testing). The standalone
patch tests run separately because these packages are excluded from workspace
membership. CI includes both test commands, strict native/WASI Clippy, release
component builds and the P3 runtime checks.

Use the existing development CLI for runtime verification:

```bash
cargo run --locked -p oidc-wasm-dev -- runtime-test
```

The CLI builds the frontend and components, checks HTTP and PostgreSQL under
Wasmtime, and stops the processes and database it creates. Use `--skip-build`
only when both components and the `http-client-smoke` probe are already built.
See the [runtime prerequisites and external database option](../README.md#testing).

The cryptographic suites cover signature verification, altered signatures,
WebAuthn registration/authentication and attestation cases. Functional tests
do not prove constant-time machine-code execution. The standalone SAML test
command runs its library tests; its additional integration corpus is not bundled
in full. Browser tests and configured third-party identity-provider journeys
remain separate from these checks.

## Remove an upstreamed patch

Follow the [removal procedure](../patches/README.md#removal) only after verifying
that the selected upstream release uses the corrected dependency chain. Include
the matching manifest and Cargo-generated lockfile changes in the same review.
Remove that package's standalone CI test command when removing its directory.
Rerun the security, application and WASI checks before publishing new artifacts.
