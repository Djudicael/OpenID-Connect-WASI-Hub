# Cryptographic dependency patches

The published `passkey-auth 0.1.3` and `saml 0.0.1-alpha.2` require P-256/P-384
0.13 and consequently `crypto-bigint 0.5.5`. That version is affected by
[RUSTSEC-2026-0387](https://rustsec.org/advisories/RUSTSEC-2026-0387.html).
The fix requires `crypto-bigint >=0.7.6`; a compatible lockfile update cannot
bridge the upstream semver requirements. Root `[patch.crates-io]` entries use
the sources here, with P-256/P-384 0.14, ECDSA 0.17 and `crypto-bigint 0.7.10`
in the root lockfile. No advisory exception was added.

## Provenance and changes

Sources were copied from the crates.io packages:

| Package | Upstream repository | Release commit |
| --- | --- | --- |
| passkey-auth 0.1.3 | https://github.com/marirs/passkey-auth-rs | `63a54b2df1cdc10d6f42b3383a761b68f8d68bf4` |
| saml 0.0.1-alpha.2 | https://github.com/danielkov/saml | `cfc67d6d6fc36a58405bb4caaf99aaff9d7cd62d` |

Original license files and library sources are retained. Packaging metadata,
example applications and their unrelated development dependencies, upstream
CI/scripts and documentation directories were omitted. The SAML response parser
test fixture omitted from its published archive was restored from the exact
release commit at `tests/corpus/ruby-saml/responses/response_with_multiple_attribute_statements.xml`.
Its ruby-saml MIT license is retained beside the fixture (from ruby-saml v1.18.1).

The patches change dependency requirements, SEC1 point API names and imports
for ECDSA 3.x signature traits and PKCS8 0.11. RSA and Ed25519 retain their existing
signature/PKCS8 traits. The WebAuthn attestation test uses X509 0.3 to generate
certificates with the new signing traits; production X509 parsing stays on 0.2.
Tests use the new P-256 key generator. SAML additionally tests both P-256 and
P-384 with PEM/DER private keys, raw/DER signatures and tampering rejection.

## Validation

Run from the repository root in WSL using the pinned Rust toolchain:

```bash
cargo test --locked --manifest-path patches/passkey-auth/Cargo.toml --lib --tests
cargo test --locked --manifest-path patches/saml/Cargo.toml --lib
cargo deny --locked check advisories bans licenses sources
cargo test --locked --workspace
cargo build --locked -p openid-connect-wasi -p oidc-admin-wasi --target wasm32-wasip2 --release
```

The patched packages are excluded from workspace membership and have their own
lockfiles for reproducible upstream tests. Their production dependencies are
resolved by the root lockfile. CI runs the upstream tests as a separate step.
The SAML integration corpus suite needs additional upstream fixtures and is not
part of this step; application integration tests run through the workspace.

## Removal

Remove each patch when a published upstream release supports the corrected
RustCrypto dependency chain. Update the corresponding workspace dependency,
remove its `[patch.crates-io]` entry and directory, refresh the root lockfile
with Cargo, and rerun the commands above plus strict native/WASI Clippy and
`oidc-wasm-dev runtime-test`. Remove the associated standalone CI test command.
Do not remove a patch merely because a newer upstream version exists: verify
that no vulnerable `crypto-bigint` version remains in `cargo tree`.
