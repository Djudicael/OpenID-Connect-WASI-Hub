# Direct WASIp3 User Federation Completion Plan

## Objective

Make LDAP, Active Directory, and Kerberos federation operate directly from the production WASI component without requiring the HTTPS federation gateway. Keep the gateway as an optional compatibility backend.

The feature is complete only when the production `wasm32-wasip3` component passes protocol-level end-to-end tests against real directory and Kerberos services.

## Current baseline

The project already provides:

- realm-scoped LDAP, Active Directory, and Kerberos provider configuration
- encrypted gateway credentials and fine-grained administration permissions
- provider connection tests and manual synchronization
- first-login user import and profile updates
- group creation and membership assignment
- LDAP and Active Directory password-login orchestration
- a Kerberos/SPNEGO login endpoint
- token `amr` values identifying the federation method
- a gateway contract test covering the identity-service workflow

The missing part is the direct protocol backend. The existing backend sends HTTPS requests to a native gateway which performs LDAP binds, directory searches, and Kerberos ticket validation.

## Completion architecture

### Provider backends

Add an explicit backend mode to each provider:

- `direct`: the WASIp3 component connects to the directory or validates Kerberos itself
- `gateway`: the existing HTTPS gateway contract

New providers should default to `direct` after the WASIp3 runtime is production-ready. Existing gateway providers must continue to work without migration downtime.

Define protocol-neutral traits so authentication and synchronization do not depend on the transport:

```rust
trait DirectoryProvider {
    async fn test_connection(&self) -> Result<TestResult, FederationError>;
    async fn authenticate(&self, identifier: &str, password: Secret<&str>)
        -> Result<Option<DirectoryUser>, FederationError>;
    async fn users(&self, cursor: Option<&str>) -> Result<DirectoryUserPage, FederationError>;
}

trait KerberosAcceptor {
    async fn accept_spnego(&self, token: &[u8], context: &RequestContext)
        -> Result<KerberosIdentity, FederationError>;
}
```

Implement gateway and direct backends behind these traits. Keep protocol errors internal and return stable, safe errors to administrators and login clients.

### Secret provisioning

Do not place bind passwords, private keys, keytabs, or ticket caches in the public provider JSON.

Support an opaque secret reference resolved through a host-provided WIT secrets interface. A preopened, read-only filesystem resource may be supported as an explicitly configured fallback for keytabs and CA bundles. Secret material must:

- remain encrypted or host-managed at rest
- never be returned by an administration API
- never appear in debug output, audit details, or traces
- be zeroized after use where the library permits it
- support rotation without recreating the provider

## Phase 1: WASIp3 platform migration

- Add the `wasm32-wasip3` Rust target to the toolchain and CI environment.
- Verify the selected Wasmtime version supports the required Preview 3 HTTP, TCP, UDP, DNS, clocks, random, and filesystem or secret imports.
- Replace or upgrade Preview 2-only server and HTTP adapters where necessary.
- Confirm PostgreSQL access works from the Preview 3 component, adapting the database client if required.
- Add a minimal WASIp3 socket probe that resolves a hostname, opens TCP, exchanges bytes, enforces a timeout, and closes cleanly.
- Preserve the native development target while the migration is in progress.
- Document the exact runtime capabilities that deployment must grant.

### Phase 1 acceptance

- `cargo build -p openid-connect-wasi --target wasm32-wasip3 --release` passes.
- A component running in Wasmtime serves the health endpoint and reaches PostgreSQL.
- The socket probe reaches a test TCP service through granted capabilities and fails cleanly when access is denied.
- Preview 3 runtime tests run in CI or the repository's standard reproducible test command.

## Phase 2: LDAP protocol and transport

Implement or adopt a WASIp3-compatible, pure-Rust LDAP stack. Reusing protocol codec code from an existing crate is acceptable when its license is compatible, but Tokio or operating-system networking must not enter the WASI dependency graph.

### Transport

- DNS lookup through WASIp3 name resolution
- TCP connections through WASIp3 sockets
- connection, read, write, and total-operation deadlines
- LDAPS with pure-Rust TLS
- LDAP StartTLS with protection against continuing after a failed upgrade
- configurable trusted roots and optional private CA bundles
- certificate hostname and validity verification
- bounded message and response sizes
- clean connection shutdown and reconnect behavior

### LDAP codec and operations

- ASN.1 BER encoding and bounded decoding for LDAP messages
- simple bind and anonymous bind only where explicitly enabled
- search requests and streamed search results
- RFC 4515 filter escaping for every user-controlled identifier
- base, one-level, and subtree search scopes
- requested-attribute selection
- paged-results control and opaque cookie handling
- server result-code mapping without leaking bind details to callers
- referrals with a disabled-by-default policy, hop limit, and allowlist
- abandon or connection cancellation when a request times out
- unbind on orderly shutdown

### LDAP mapping

- stable external identifier, username, email, names, display name, enabled state, groups, and custom attributes
- configurable user and group base DNs and filters
- deterministic behavior for missing or duplicate email addresses
- binary attribute support where needed for stable identifiers
- schema and connection validation in the administration connection test

### Phase 2 acceptance

- A production WASIp3 component connects directly to OpenLDAP with no gateway configured.
- Plain LDAP is allowed only when an administrator explicitly enables it for a development/test provider.
- StartTLS and LDAPS succeed with a trusted certificate and reject untrusted, expired, or wrong-host certificates.
- Valid and invalid binds, escaped identifiers, paging, timeouts, oversized responses, and referral policy have automated tests.
- Password bytes are not stored, logged, placed in URLs, or copied into user attributes.

## Phase 3: Active Directory compatibility

Build Active Directory behavior on the direct LDAP backend:

- bind using configured service-account and user-bind strategies
- authenticate identifiers using reviewed templates for `userPrincipalName`, `sAMAccountName`, and distinguished name
- use `objectGUID` as a stable binary external identifier with a canonical encoding
- interpret `userAccountControl` for disabled accounts
- map `memberOf`, primary group, and configured nested groups
- handle ranged multi-valued attributes returned by Active Directory
- support the AD paged-results behavior used for large directories
- support Global Catalog endpoints when explicitly configured
- define and test username/email changes without creating duplicate local users
- reject ambiguous searches that return multiple users
- make nested-group depth and result counts configurable and bounded

### Phase 3 acceptance

- The WASIp3 component authenticates and synchronizes users directly against an Active Directory-compatible test domain.
- Disabled accounts cannot create new sessions.
- `objectGUID` continues to link the same local user after username, email, or DN changes.
- Direct, primary, and configured nested group memberships reconcile correctly.
- Large and ranged group results are covered by automated tests.

## Phase 4: Synchronization correctness

Expand synchronization from import/update into a complete lifecycle:

- full synchronization with a generation marker or equivalent bounded reconciliation mechanism
- incremental synchronization when the directory exposes a safe change token
- configurable behavior for users missing from a completed full sync: disable, unlink, or retain
- re-enable a previously disabled linked user when the directory account becomes active again, according to policy
- record which provider owns each synchronized group membership
- add new provider-owned memberships and remove stale provider-owned memberships
- never remove memberships assigned locally or by another provider
- detect a reused or changed external identifier safely
- expose imported, updated, disabled, unlinked, skipped, and failed counts
- store a safe error summary and an administrator-visible per-run result
- make repeated pages and repeated complete syncs idempotent
- provide an authenticated sync endpoint suitable for an external scheduler; do not require background threads

### Phase 4 acceptance

- Two identical synchronizations produce the same local state without duplicates.
- Renames update the existing account.
- Removed and disabled directory users follow the configured lifecycle policy.
- Stale directory-owned group memberships are removed while local memberships remain.
- A failed or truncated sync never treats unseen users as deleted.
- Concurrent sync attempts for one provider are serialized or one is rejected safely.

## Phase 5: Direct Kerberos and SPNEGO

Choose one of these production designs after a bounded prototype:

1. A pure-Rust Kerberos/SPNEGO acceptor compiled into the component.
2. A narrow host WIT capability which accepts SPNEGO and returns a verified principal plus ticket metadata.

The pure-Rust design is preferred for portability if it supports the required encryption types and can be independently reviewed. The host capability is acceptable when its contract is versioned, capability-scoped, and tested on every supported runtime.

### Required Kerberos behavior

- strict `Authorization: Negotiate` parsing and base64 decoding
- SPNEGO token parsing without accepting NTLM fallback
- Kerberos AP-REQ verification for the configured HTTP service principal
- AES session-key and service-key encryption types required by the supported domain policy
- key selection by principal, version, and encryption type
- ticket start, expiry, renewable, and clock-skew validation
- service-principal/audience validation
- authenticator validation
- replay protection shared across component instances, backed by PostgreSQL or a host service with atomic insert-if-absent semantics
- principal canonicalization and explicit realm allowlisting
- principal-to-directory-user resolution through the direct LDAP/AD backend
- safe handling of key rotation with overlapping key versions
- `WWW-Authenticate: Negotiate` on authentication challenges
- bounded token sizes and parsing work

### Phase 5 acceptance

- A client obtains a real ticket from the test KDC and signs in through the production WASIp3 component without a gateway.
- Invalid, expired, replayed, wrong-realm, wrong-service, malformed, and unsupported-encryption tickets are rejected.
- Replaying a ticket against another component instance is rejected.
- Key rotation succeeds without accepting tickets encrypted for retired keys after the overlap expires.
- Successful sessions and tokens contain the correct `kerberos` authentication method and still enforce MFA, required actions, and step-up rules.

## Phase 6: Administration and operations

- Add backend selection and direct connection fields to the existing User Federation page.
- Show fields appropriate to LDAP, Active Directory, or Kerberos and hide irrelevant gateway fields.
- Replace free-form JSON for standard connection and mapping options with validated form controls; retain an advanced attributes object only for non-secret extensions.
- Make connection testing verify DNS, TCP, TLS, bind, base DN, mappings, and Kerberos key availability as separate safe steps.
- Add audit events for provider create, update, delete, connection test, secret rotation, synchronization, and backend changes.
- Add metrics for connection latency, authentication outcomes, synchronization outcomes, imported users, directory errors, and Kerberos replay rejection without high-cardinality user labels.
- Add health/readiness reporting for configuration validity without making a temporary directory outage fail the identity service globally.
- Document secret rotation, certificate rotation, directory outages, account conflicts, and rollback to the gateway backend.

## Protocol-level end-to-end environment

Add a reproducible test topology under `tests/federation/` or the existing integration-test tooling:

- OpenLDAP with seeded users, groups, paging data, and a test CA
- an Active Directory-compatible domain controller with LDAP, DNS, and Kerberos enabled
- a Kerberos client/test driver able to acquire service tickets
- PostgreSQL
- Wasmtime running the actual release WASIp3 component

Tests must call the public administration and login endpoints. Directly invoking internal LDAP or Kerberos functions is useful for unit tests but does not satisfy end-to-end completion.

### Required scenarios

- LDAP connection test, bind login, first-login import, full sync, rename, disable, deletion policy, group addition, and group removal
- LDAP injection attempts and malformed BER responses
- StartTLS and LDAPS success and certificate failures
- Active Directory login by UPN and `sAMAccountName`
- stable `objectGUID` linking across rename
- primary, direct, nested, large, and ranged group memberships
- Kerberos ticket acquisition and browser-equivalent Negotiate login
- invalid, expired, replayed, wrong-service, and wrong-realm Kerberos tickets
- directory outage, timeout, interrupted sync, recovery, and gateway fallback
- multi-realm isolation and fine-grained administration permissions
- MFA, required actions, organization membership, client roles, protocol mappers, offline sessions, and audit events for a federated user

The test suite must prove the direct backend is used by running with no gateway URL or gateway process.

## Security review gates

Before declaring completion:

- review BER and SPNEGO parsers for panics, unbounded allocation, recursion, and algorithm confusion
- fuzz BER messages, LDAP controls, filters, SPNEGO tokens, Kerberos tickets, keytab parsing, and mapping configuration
- verify constant-time comparison where protocol secrets or authenticators require it
- run dependency and license review for any imported protocol code
- confirm TLS verification cannot be disabled in production configuration
- threat-model LDAP injection, malicious directory responses, referral attacks, credential disclosure, Kerberos replay, cross-realm confusion, and account-link takeover
- confirm logs, traces, metrics, errors, and audit records contain no passwords, bind secrets, key material, raw tickets, or sensitive directory attributes

## Migration and compatibility

- Add database migrations for backend mode, direct connection settings, secret references, sync ownership/generation state, and Kerberos replay records.
- Default existing providers to `gateway` so upgrades preserve behavior.
- Permit administrators to test a direct backend before switching an existing provider.
- Keep linked-user external identifiers stable during backend changes.
- Provide rollback from `direct` to `gateway` without relinking users.
- Deprecate no gateway API until direct federation has operated successfully in supported production environments.

## Definition of complete

The feature may return to **Complete** in `tempo.md` only when all of these conditions hold:

- The supported production target is `wasm32-wasip3` and its release build passes.
- LDAP and Active Directory authentication and synchronization run directly from the component.
- Kerberos/SPNEGO validation runs through pure WASI-compatible code or an explicitly supported host WIT capability.
- The gateway is optional and no direct-backend test starts one.
- Full user and provider-owned group reconciliation is implemented safely.
- Secrets, TLS validation, timeouts, limits, replay protection, and audit coverage pass review.
- Protocol-level tests pass against OpenLDAP, an Active Directory-compatible domain, and a Kerberos KDC.
- The complete workspace, frontend, native integration, and Wasmtime WASIp3 suites pass.
- Administrator and operator documentation describes the verified direct workflow with screenshots from a running build.

## Suggested implementation order

1. WASIp3 runtime and socket proof.
2. Backend traits and compatibility migration.
3. Direct LDAP transport, codec, bind, and search.
4. TLS, paging, mapping, and OpenLDAP end-to-end tests.
5. Active Directory behavior and domain end-to-end tests.
6. Full user and group reconciliation.
7. Kerberos architecture prototype and review decision.
8. Kerberos/SPNEGO implementation and KDC end-to-end tests.
9. Administration, audit, metrics, operational documentation, fuzzing, and final security review.
