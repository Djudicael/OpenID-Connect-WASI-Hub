# OpenID Connect Implementation Gap Analysis

## Legend
- ✅ **Implemented / Supported** — Available and part of the supported feature set
- 🟡 **Partial / Limited** — Works but with important interoperability, deployment, or hardening caveats
- ❌ **Missing / Not Supported** — Not implemented or intentionally not supported

This file is a capability matrix, not a blanket claim that every ✅ item is equally hardened for every production deployment shape.

---

## 1. OIDC Flows (OpenID Connect Core 1.0 §3)

| Flow | Status | Notes |
|------|--------|-------|
| Authorization Code (+ PKCE) | ✅ | Primary flow. Mandatory S256 PKCE. |
| Refresh Token | ✅ | With rotation + theft detection (token family). |
| Client Credentials | ✅ | No ID Token or refresh token. |
| Resource Owner Password Credentials | ✅ | Via `/login` only (first-party). Not exposed via token endpoint. |
| Implicit Flow (§3.2) | ✅ | `response_type=token`, `id_token`, `id_token token` supported |
| **Hybrid Flow** (§3.3) | ✅ | `response_type=code token`, `code id_token`, `code id_token token` supported |

---

## 2. OIDC Endpoints

| Endpoint | Status | Spec |
|----------|--------|------|
| Authorization (`/authorize`) | ✅ | Core §3.1 |
| Token (`/token`) | ✅ | Core §3.1 |
| UserInfo (`/userinfo`) | ✅ | Core §5.3 |
| JWKS (`/jwks`) | ✅ | Core §10 |
| Discovery (`/.well-known/openid-configuration`) | ✅ | Discovery §4 |
| Dynamic Client Registration (`/register`) | ✅ | Registration §3 |
| RP-Initiated Logout (`/logout`) | ✅ | Session §5 |
| Token Introspection (`/introspect`) | ✅ | RFC 7662 |
| Token Revocation (`/revoke`) | ✅ | RFC 7009 |
| **Pushed Authorization Requests (`/par`)** | ✅ | RFC 9126 |
| **WebFinger Discovery** (`/.well-known/webfinger`) | ✅ | Discovery §5 |
| **Check Session Iframe** | ❌ | Session §4 — intentionally not advertised; endpoint returns `501 Not Implemented` |
| **Back-Channel Logout** | ✅ | Backchannel §7 |

---

## 3. Authorization Request Parameters (Core §3.1.2)

| Parameter | Status | Notes |
|-----------|--------|-------|
| `response_type` | ✅ | `code`, `token`, `id_token`, `code token`, `code id_token`, `id_token token`, `code id_token token` |
| `client_id` | ✅ | |
| `redirect_uri` | ✅ | |
| `scope` | ✅ | |
| `state` | ✅ | |
| `nonce` | ✅ | In AuthCode & ID Token |
| `prompt` | ✅ | `none`, `login`, `consent` |
| `max_age` | ✅ | |
| `login_hint` | ✅ | Email pre-fill |
| `code_challenge` / `code_challenge_method` | ✅ | Mandatory S256 |
| `display` | ✅ | `page`, `popup`, `touch`, `wap` |
| `claims` | ✅ | Stored in auth code, passed to token endpoint |
| `claims_locales` | ✅ | Parsed, stored in AuthCode, resolved via `resolve_locale()` for ID token `locale` claim (OIDC Core §3.1.2.1 / §5.2). Advertised in discovery as `claims_locales_supported`. |
| `id_token_hint` | ✅ | Verified in authorize endpoint: extracts `sub` from hint JWT, checks if authenticated user matches. Returns `account_selection_required` (prompt=none) or redirects to login if mismatch (OIDC Core §3.1.2.2). Also used as user lookup source (priority 3 after session cookie and login_hint). |
| `acr_values` | ✅ | Validated against supported ACR values. Resolved via `resolve_acr_amr()` based on authentication method. Returns `login_required` if requested ACR cannot be satisfied (OIDC Core §3.1.2.2). ACR/AMR claims now use resolved values instead of hardcoded strings. |
| `request` (Request Object JWT) | ✅ | JWT-signed authorization requests per Core §6. RS256 + EdDSA via client JWKS |
| `request_uri` | 🟡 | Supported for PAR-issued `urn:ietf:params:oauth:request_uri:*` values; not a general remote/fetched request URI feature |

---

## 4. ID Token Claims (Core §2)

| Claim | Status | Notes |
|-------|--------|-------|
| `iss` | ✅ | Issuer identifier |
| `sub` | ✅ | Subject identifier |
| `aud` | ✅ | Audience (client_id) |
| `exp` | ✅ | Expiration |
| `iat` | ✅ | Issued at |
| `auth_time` | ✅ | Authentication time |
| `nonce` | ✅ | |
| `at_hash` | ✅ | Access token hash |
| `c_hash` | ✅ | Code hash |
| `acr` | ✅ | Dynamically resolved via `resolve_acr_amr()` based on authentication method and requested `acr_values` |
| `amr` | ✅ | Dynamically resolved via `resolve_acr_amr()` — supports `pwd`, `mfa`, `otp`, `sms`, `device_code`, `token_exchange`, `social` |
| `azp` | ✅ | Authorized party — set to `client_id` when resource indicators are present (OIDC Core §2, RFC 8707) |

---

## 5. UserInfo Claims (Core §5.1, §5.2)

| Claim | Status | Notes |
|-------|--------|-------|
| `sub` | ✅ | |
| `name` | ✅ | |
| `given_name` | ✅ | |
| `family_name` | ✅ | |
| `email` | ✅ | |
| `email_verified` | ✅ | |
| `middle_name` | ✅ | |
| `nickname` | ✅ | |
| `preferred_username` | ✅ | |
| `profile` | ✅ | Profile URL |
| `picture` | ✅ | |
| `website` | ✅ | |
| `gender` | ✅ | |
| `birthdate` | ✅ | |
| `zoneinfo` | ✅ | |
| `locale` | ✅ | Returned in ID Token and UserInfo |
| `phone_number` | ✅ | Returned in UserInfo |
| `phone_number_verified` | ✅ | Returned in ID Token and UserInfo |
| `address` | ✅ | Structured address (OIDC Core §5.1.1). `AddressClaim` model with `formatted`, `street_address` (multi-line `\n` for European addresses), `locality`, `region` (generic: US state, French région, German Bundesland), `postal_code` (any format), `country` (ISO 3166-1). Auto-generated `formatted` field uses European-friendly format (postal code before city). Returned in UserInfo when `address` scope is present, and in ID token when `address` scope is requested. V35 migration adds address columns to users table. |
| `updated_at` | ✅ | Returned in ID Token and UserInfo |

---

## 6. Subject Identifier Types (Core §8)

| Type | Status | Notes |
|------|--------|-------|
| `public` | ✅ | Default (direct user ID or UUID) |
| `pairwise` | ✅ | Per-sector-identifier pseudonyms via `SHA256(user_id|sector|salt)` base64url |
| `sector_identifier_uri` | ✅ | Supported on Client model; falls back to first redirect_uri host |

---

## 7. Token Authentication Methods

| Method | Status | Spec |
|--------|--------|------|
| `client_secret_basic` | ✅ | RFC 6749 §2.3.1 |
| `client_secret_post` | ✅ | RFC 6749 §2.3.1 |
| `client_secret_jwt` | ✅ | RFC 7523 — HMAC-signed JWT (HS256/HS384/HS512) with reversible secret storage (AES-256-GCM encrypted) |
| `private_key_jwt` | ✅ | RFC 7523 — RS256 + EdDSA via inline `jwks` |
| `tls_client_auth` | ❌ | RFC 8705 — requires reverse proxy to forward client cert headers (e.g. `X-Forwarded-Client-Cert`) |
| `self_signed_tls_client_auth` | ❌ | RFC 8705 — same as above |
| `none` (public clients) | ✅ | |

---

## 8. Response Types (Core §3)

| Type | Status | Notes |
|------|--------|-------|
| `code` | ✅ | Authorization Code Flow |
| `token` | ✅ | Implicit Flow |
| `id_token` | ✅ | Implicit Flow |
| `code token` | ✅ | Hybrid Flow |
| `code id_token` | ✅ | Hybrid Flow |
| `id_token token` | ✅ | Implicit Flow |
| `code id_token token` | ✅ | Hybrid Flow |

---

## 9. Grant Types (RFC 6749 + Extensions)

| Grant | Status | Notes |
|-------|--------|-------|
| `authorization_code` | ✅ | |
| `client_credentials` | ✅ | |
| `refresh_token` | ✅ | |
| `password` | 🟡 | Internal `/login` only |
| `urn:ietf:params:oauth:grant-type:device_code` | ✅ | Device Authorization (RFC 8628) |
| `urn:ietf:params:oauth:grant-type:token-exchange` | ✅ | Token Exchange (RFC 8693) |
| `urn:ietf:params:oauth:grant-type:jwt-bearer` | ✅ | JWT Bearer (RFC 7523) |

---

## 10. Security Features

| Feature | Status | Notes |
|---------|--------|-------|
| PKCE S256 | ✅ | Mandatory |
| Refresh Token Rotation | ✅ | |
| Refresh Token Theft Detection | ✅ | Token family, reuse marking |
| Brute-Force Protection | ✅ | 5 attempts / 5 min via audit trail |
| Timing-Attack Protection | ✅ | Dummy hash on unknown user |
| Rate Limiting | 🟡 | Per-IP, configurable, but in-process/per-instance unless an upstream shared gateway/CDN limiter is the production source of truth |
| CORS | ✅ | Configurable origins |
| Security Headers | ✅ | CSP, HSTS, X-Frame-Options, etc. |
| HMAC Session Cookies | ✅ | HttpOnly, Secure, SameSite |
| JWT Bearer Token Auth | ✅ | RS256 + EdDSA |
| Token Hashing (at rest) | ✅ | SHA-256 |
| Secret Hashing (at rest) | ✅ | Argon2id |
| **Signed Request Objects** | ✅ | JWT-signed authorization requests per Core §6. RS256 + EdDSA via client JWKS |
| **Encrypted Request Objects** | 🟡 | JWE-encrypted requests (dir + RSA-OAEP-256 with A256GCM). Advanced/limited-interoperability feature rather than a broad production default claim. |
| **Encrypted ID Tokens** | 🟡 | JWE-encrypted ID Tokens (dir + RSA-OAEP-256 with A256GCM). Advanced feature; not the primary/default interoperability posture. |
| **mTLS** | ❌ | Mutual TLS — requires reverse proxy to forward client cert headers to WASM component |
| **DPoP** | 🟡 | RFC 9449-style proof validation and `cnf.jkt` token binding exist, but replay detection is not persisted across requests/instances |
| **PAR** (Pushed Authorization Requests) | ✅ | RFC 9126 |
| **JARM** (JWT Authorization Response Mode) | ✅ | RFC 9101 — JWT-secured authorization responses (query.jwt, fragment.jwt, form_post.jwt) |

---

## 11. Session Management

| Feature | Status | Spec |
|---------|--------|------|
| RP-Initiated Logout | ✅ | Session §5 |
| Session Cookie | ✅ | `oidc_session`, HMAC-protected |
| **Check Session Iframe** (`check_session_iframe`) | ❌ | Session §4 — intentionally not supported/advertised; endpoint returns `501 Not Implemented` |
| **Session State** (`session_state`) | ✅ | Session §3 — `SHA256(client_id + " " + sid + " " + origin)` base64url in authorize response |
| **Front-Channel Logout** | ✅ | Front-Channel §6 — HTML page with iframes to each RP's `frontchannel_logout_uri` with `iss` + optional `sid` |
| **Back-Channel Logout** | ✅ | Back-Channel §7 — Signed logout tokens via HTTP POST to each RP's `backchannel_logout_uri` with `events` claim |

---

## 12. Signing & Encryption

| Feature | Status | Notes |
|---------|--------|-------|
| RS256 (RSA + SHA-256) | ✅ | Primary signing algorithm |
| EdDSA (Ed25519) | ✅ | Secondary signing algorithm |
| Key Rotation | ✅ | Active/retired/expired lifecycle |
| JWKS | ✅ | Both RSA and Ed25519 |
| Per-Realm Keys | ✅ | Realm-specific signing keys |
| Key Generation (WASM) | ✅ | RSA 2048 + Ed25519, pure Rust |
| **RS384, RS512** | ❌ | Only RS256 |
| **ES256, ES384, ES512** (ECDSA) | ❌ | |
| **PS256, PS384, PS512** (RSA-PSS) | ❌ | |
| **HS256, HS384, HS512** (HMAC) | ❌ | Not recommended for OIDC |
| **JWE Encryption** | ✅ | dir + RSA-OAEP-256 with A256GCM |
| **Nested JWT (sign then encrypt)** | ✅ | Sign then encrypt for ID tokens |

---

## 13. Management / Admin Features

| Feature | Status | Notes |
|---------|--------|-------|
| User CRUD | ✅ | Via admin API |
| Client CRUD | ✅ | Via admin API |
| Realm (multi-tenant) | ✅ | Full multi-realm support |
| Scope Management | ✅ | Via admin API |
| API Key Management | ✅ | Full key lifecycle |
| Session Listing/Revocation | ✅ | Via admin API |
| Audit Trail | ✅ | Comprehensive event logging |
| Health Checks | ✅ | /health, /live, /ready |
| Admin UI (Web Components) | ✅ | Native WC + lit-html |
| **Console Admin User Mgmt** | ✅ | Full user management with groups/roles in admin UI |
| **User Groups / Roles** | ✅ | Full RBAC model: `Role` and `Group` models with permissions, hierarchical groups, user-role/group junction tables, group-role junction tables, admin API endpoints for CRUD and assignment, `roles` and `groups` claims in ID tokens and UserInfo |
| **Password Policies** | ✅ | Per-realm configurable `PasswordPolicy` stored in realm `config` JSONB: min/max length, uppercase/lowercase/digit/special requirements, unique chars, consecutive identical limit, disallowed passwords list. Validated at user creation, password change, password reset, and account recovery. V36 migration seeds default policy on existing realms. |
| **Email Verification Flow** | ✅ | Token-based email verification with `EmailSender` trait, `/oidc/email-verification/request` and `/oidc/email-verification/confirm` endpoints, 24h token expiry, anti-enumeration |
| **Password Reset Flow** | ✅ | Self-service password reset with `/oidc/password-reset/request` and `/oidc/password-reset/confirm` endpoints, 15min token expiry, anti-enumeration, single-use tokens |
| **Account Recovery** | ✅ | Admin-initiated account recovery with `AccountRecoveryToken` model (SHA-256 hashed, 24h expiry, single-use). Admin endpoint `POST /api/users/{id}/account-recovery` generates one-time recovery link. Public confirmation endpoint `POST /oidc/account-recovery/confirm` validates token and sets new password against realm policy. Full audit trail (`user.account_recovery_initiated`, `user.account_recovery_completed`). V38 migration creates `account_recovery_tokens` table. |
| **User Impersonation** | ✅ | Admin impersonation via `POST /api/users/{id}/impersonate`. Issues short-lived (5 min) access token with RFC 8693-style `act` claim identifying the admin. Full audit trail (`user.impersonated`). Uses `JwtTokenService::encode_access_token_with_act()`. |
| **Scheduled Token Cleanup** | ✅ | Admin endpoint `POST /api/maintenance/cleanup` triggers cleanup of expired sessions, password reset tokens, email verification tokens, account recovery tokens, device codes, authorization codes, and PAR requests. Returns per-table deletion counts. Designed for external cron scheduler (WASM cannot run background threads). Audit event: `maintenance.cleanup`. |

---

## 14. Federation / Social Login

| Feature | Status | Notes |
|---------|--------|-------|
| **OIDC Identity Provider** (upstream OIDC) | ✅ | Act as RP to external IdP — code exchange, userinfo fetch, local user creation/linking |
| **SAML Identity Provider** | ❌ | |
| **Social Login** (Google, GitHub, etc.) | ✅ | Generic OIDC + Google + GitHub provider types, auto-create users, link by email |
| **Identity Brokering** | ✅ | `IdentityProvider` model with per-realm configuration, `FederatedIdentity` linking |
| **User Linking** | ✅ | Link existing users by email (`link_users_by_email`), auto-create (`auto_create_users`) |

---

## 15. OAuth2 Extensions

| Feature | Status | Spec |
|---------|--------|------|
| Token Introspection | ✅ | RFC 7662 |
| Token Revocation | ✅ | RFC 7009 |
| Dynamic Registration | ✅ | RFC 7591 |
| **Pushed Authorization Requests (PAR)** | ✅ | RFC 9126 |
| **JWT-Secured Authorization Response Mode (JARM)** | ✅ | RFC 9101 |
| **Token Exchange** | ✅ | RFC 8693 |
| **Device Authorization Grant** | ✅ | RFC 8628 |
| **JWT Bearer Token** | ✅ | RFC 7523 |
| **Resource Indicators** | ✅ | RFC 8707 |
| **Rich Authorization Requests (RAR)** | ✅ | RFC 9396 |

---

## Summary & Recommendations

### What Is Mature / Supported for current deployment posture:
- Core Authorization Code flow with mandatory PKCE
- All standard OIDC endpoints (authorize, token, userinfo, jwks, discovery, register)
- Token lifecycle (issue, introspect, revoke, refresh with rotation + theft detection)
- Security baseline: Argon2id secrets, brute-force protection, security headers, CORS, and a local rate-limiting safety net
- Multi-tenant (realms) with per-realm signing keys
- Admin API + SPA for management
- Comprehensive audit trail
- Pure Rust, WASM-compatible crypto (no OpenSSL)
- **PAR (RFC 9126)** — pushed authorization requests for enhanced security
- **Private-key JWT client auth (RFC 7523)** — asymmetric client authentication via inline JWKS
- **Signed Request Objects (OIDC Core §6)** — JWT-signed authorization requests verified against client JWKS
- **DPoP (RFC 9449)** — partial sender-constrained-token support with `cnf.jkt` binding and proof verification at token and userinfo endpoints; replay persistence remains a gap
- **Session State (Session §3)** — `session_state` parameter in authorization response, computed as `SHA256(client_id + " " + sid + " " + origin)` base64url
- **Front-Channel Logout (Front-Channel §6)** — HTML page with iframes to each RP's `frontchannel_logout_uri` with `iss` + optional `sid`
- **Back-Channel Logout (Back-Channel §7)** — Signed logout tokens via HTTP POST to each RP's `backchannel_logout_uri` with `events` claim
- **Pairwise Subject Identifiers (Core §8)** — Per-sector pseudonymous `sub` values via `SHA256(user_id|sector|salt)` base64url. Client model includes `subject_type` and `sector_identifier_uri`. Discovery includes `subject_types_supported: ["public", "pairwise"]`.
- **ACR / AMR (Core §2)** — `acr` and `amr` claims in ID tokens. Dynamic ACR/AMR resolution via `resolve_acr_amr()` based on authentication method (pwd, mfa, otp, sms, device_code, token_exchange, social). Supported ACR values: `urn:mace:incommon:iap:bronze` (single-factor), `urn:mace:incommon:iap:silver` (MFA). Supported AMR values: `pwd`, `mfa`, `otp`, `sms`, `device_code`, `token_exchange`, `social`. `acr_values` parameter validated in authorization requests; returns `login_required` if requested ACR cannot be satisfied (OIDC Core §3.1.2.2). `claims_locales` parameter resolved via `resolve_locale()` for ID token `locale` claim (OIDC Core §5.2). `id_token_hint` parameter verified in authorize endpoint with `account_selection_required` error on mismatch (OIDC Core §3.1.2.2). Discovery includes `acr_values_supported`, `amr_values_supported`, `claims_locales_supported`, and `acr`/`amr` in `claims_supported`. V24 migration adds `acr_values` column; V34 migration adds `claims_locales` column to authorization_codes table.
- **id_token_hint in Authorize (Core §3.1.2.1)** — The `id_token_hint` parameter is verified in the authorize endpoint: the OP extracts the `sub` claim from the hint JWT (with best-effort signature verification, falling back to unverified payload extraction), checks if the currently authenticated user matches the hint subject, and returns `account_selection_required` (with prompt=none) or redirects to login if there's a mismatch. The hint subject is also used as a user lookup source (priority 3 after session cookie and login_hint).
- **claims_locales (Core §5.2)** — The `claims_locales` parameter in authorization requests specifies the end-user's preferred languages/scripts for claims. Stored in `AuthCode.claims_locales`, resolved via `resolve_locale()` which selects the best matching locale from the user's preference and the requested locales. The resolved locale is used for the ID token `locale` claim. Advertised in discovery as `claims_locales_supported`.
- **Structured Address Claim (Core §5.1.1)** — `AddressClaim` model with `formatted`, `street_address` (multi-line `\n` for European addresses like French BP/CEDEX), `locality`, `region` (generic for any locale: US state, French région, German Bundesland, Spanish comunidad autónoma), `postal_code` (any format: US 5-digit, French 5-digit, UK alphanumeric, Dutch 4-digit+2-letter), `country` (ISO 3166-1 alpha-2). Auto-generated `formatted` field uses European-friendly formatting (postal code before city). Returned in UserInfo when `address` scope is present, and in ID token when `address` scope is requested. User model stores address components in separate columns for queryability. V35 migration adds address columns to users table. Discovery includes `address` in `claims_supported` and `"address"` in `scopes_supported`.
- **Password Reset Flow** — Self-service password reset with `/oidc/password-reset/request` and `/oidc/password-reset/confirm` endpoints. 15-minute single-use tokens, anti-enumeration, `EmailSender` trait for pluggable email delivery.
- **Email Verification** — Token-based email verification with `/oidc/email-verification/request` and `/oidc/email-verification/confirm` endpoints. 24-hour single-use tokens, anti-enumeration, `EmailSender` trait.
- **Social Login / Federation** — Upstream OIDC identity provider integration. `IdentityProvider` model (Oidc, Google, GitHub types) with per-realm configuration. `FederatedIdentity` model links local users to upstream subjects. Auto-create users, link by email. Code exchange + userinfo fetch via `reqwest` (native) / `wstd` (WASI P2).
- **Device Authorization Grant (RFC 8628)** — For headless/input-constrained devices. `DeviceCode` model with SHA-256 hashed device codes, consonant-only user codes (XXXX-XXXX), 15-minute expiry. Three endpoints: `POST /oidc/device/authorize`, `GET /oidc/device`, `POST /oidc/device/confirm`. Token endpoint supports `urn:ietf:params:oauth:grant-type:device_code` with `authorization_pending`, `slow_down`, `expired_token` errors.
- **Token Exchange (RFC 8693)** — Token delegation and impersonation. Supports `access_token`, `refresh_token`, `id_token` as subject/actor tokens. Issues `access_token`, `refresh_token`, or `id_token` per `requested_token_type`. Includes `issued_token_type`, `may_act`, `act` claims. Confidential clients only.
- **JWT Bearer Grant (RFC 7523 §2.1)** — Client authentication via signed JWT assertions. Verifies signature against client JWKS. Supports `sub == iss` (client on own behalf) and `sub != iss` (delegation).
- **JWE Encrypted ID Tokens** — Advanced compatibility feature for selected algorithms (`dir` and `RSA-OAEP-256` with `A256GCM`), not the default interoperability posture.
- **JARM (RFC 9101)** — JWT-Secured Authorization Response Mode. Supports `query.jwt`, `fragment.jwt`, `form_post.jwt`, and `jwt` (auto-resolved). All authorization response parameters wrapped in a JWT signed by the OP.
- **RAR (RFC 9396)** — Rich Authorization Requests. `AuthorizationDetail` model with `type`, `locations`, `actions`, `datatypes`, `identifier`, `privileges`, and extensible fields. `authorization_details` parameter stored in auth codes and sessions, included in access token claims and introspection responses.
- **WebFinger (RFC 7033 / OIDC Discovery §5)** — OpenID Connect Discovery via webfinger. `GET /.well-known/webfinger?resource=acct:user@example.com` returns the OIDC issuer URL for the user's realm.
- **Resource Indicators (RFC 8707)** — `resource` parameter in authorization and token requests specifies target resource server URIs. Access token `aud` includes resource indicators when present, with `azp` (authorized party) set to the client_id. Discovery includes `resource_parameter_supported: true`. V33 migration adds `resource` JSONB column to authorization_codes and sessions.
- **RBAC (Roles & Groups)** — Full role-based access control. `Role` model with permissions (e.g., `["users:read", "users:write"]`), `Group` model with hierarchical parent groups. Junction tables: `user_roles`, `user_groups`, `group_roles`. Admin API endpoints for CRUD and assignment. `roles` and `groups` claims included in ID tokens (authorization_code flow) and UserInfo response. Discovery includes `roles` and `groups` in `claims_supported`. V36 migration creates `roles`, `groups`, `user_roles`, `user_groups`, `group_roles` tables with indexes.
- **Password Policies** — Per-realm configurable `PasswordPolicy` stored in `realms.config` JSONB under `"password_policy"` key. Supports: min/max length, uppercase/lowercase/digit/special requirements, min unique chars, max consecutive identical chars, disallowed passwords list (case-insensitive). Validated at user creation, password change, password reset, and account recovery. `PasswordPolicy::from_realm_config()` extracts from realm config with fallback to defaults. `PasswordPolicyViolation` returns all violated rule names. V37 migration seeds default policy on existing realms.
- **Account Recovery** — Admin-initiated account recovery for users who have lost all access methods. `AccountRecoveryToken` model (SHA-256 hashed, 24h expiry, single-use, tracks creator IP). Admin endpoint `POST /api/users/{id}/account-recovery` generates one-time recovery link. Public confirmation endpoint `POST /oidc/account-recovery/confirm` validates token and sets new password against realm policy. Full audit trail (`user.account_recovery_initiated`, `user.account_recovery_completed`). V38 migration creates `account_recovery_tokens` table.
- **User Impersonation** — Admin can impersonate any user via `POST /api/users/{id}/impersonate`. Issues a short-lived (5 min) access token with RFC 8693-style `act` claim identifying the admin. Full audit trail (`user.impersonated`). `JwtTokenService::encode_access_token_with_act()` method for impersonation tokens.
- **Token Cleanup** — Admin endpoint `POST /api/maintenance/cleanup` triggers cleanup of expired records across all token/session tables (sessions, password reset tokens, email verification tokens, account recovery tokens, device codes, authorization codes, PAR requests). Returns per-table deletion counts. Designed for external cron scheduler (WASM cannot run background threads). Audit event: `maintenance.cleanup`.
- **client_secret_jwt (RFC 7523)** — HMAC-based JWT client authentication (HS256/HS384/HS512). Client secret stored in AES-256-GCM encrypted form (`client_secret_encrypted`) for reversible retrieval at auth time. Wired into all 5 client authentication endpoints (token, device, PAR, introspect, revoke). Discovery includes `token_endpoint_auth_methods_supported` and `token_endpoint_auth_signing_alg_values_supported`.
- **Encrypted Request Objects (OIDC Core §10)** — JWE-encrypted authorization requests. Supports `dir` (direct symmetric key with A256GCM) and `RSA-OAEP-256` (RSA key wrapping with A256GCM). Nested JWT pattern: sign-then-encrypt. Authorize endpoint detects 5-part JWE, decrypts using client's configured encryption keys, then processes the inner signed JWT. Client model includes `request_object_encryption_alg`, `request_object_encryption_enc`, `request_object_encryption_key_encrypted`, `request_object_encryption_key_pem`. Discovery includes `request_object_encryption_alg_values_supported` and `request_object_encryption_enc_values_supported`. V39 migration adds request object encryption columns to clients table.

### Recommended Gaps to Fill (by priority):

#### **Phase 1 — Core OIDC Completeness (High Priority)**
1. ✅ **Full Standard Claims** — `middle_name`, `nickname`, `preferred_username`, `profile`, `picture`, `website`, `gender`, `birthdate`, `zoneinfo`, `phone_number_verified`, `updated_at` added to User model, ID Token, and UserInfo responses
2. ✅ **`locale` claim** — Returned from User model in ID Token and UserInfo
3. ✅ **`phone_number` claim** — Returned from User model in UserInfo
4. ✅ **`display` parameter** — Supported `page`, `popup`, `touch`, `wap` in authorize endpoint and discovery
6. ✅ **`claims` parameter** — Stored in auth code (`claims_request`), passed through to token endpoint per Core §5.5
7. ✅ **Per-realm signing keys wired** — All four token flows (password, authorization_code, refresh_token, client_credentials) now use `token_service_for_realm(realm_id)`
8. ✅ **Per-realm JWKS endpoint** — `/realms/{realm}/protocol/openid-connect/certs` returns realm-specific keys
9. ✅ **Implicit + Hybrid Flows** — `response_type` supports `token`, `id_token`, `code token`, `code id_token`, `id_token token`, `code id_token token`. Tokens issued directly in authorize redirect.

#### **Phase 2 — Security & Token Management (High Priority)**
1. ✅ **Signed Request Objects** (`request` parameter) — JWT-signed authorization requests per Core §6. Implemented in `crates/oidc-oidc/src/tokens/request_object.rs`. Verifies `iss`, `aud`, `exp`, `iat`, `nbf`, rejects `request_uri` inside request objects, validates signature against client JWKS (RS256 + EdDSA). Wired into authorize endpoint. Discovery includes `request_parameter_supported` and `request_object_signing_alg_values_supported`.
2. ✅ **Pushed Authorization Requests (PAR)** — RFC 9126 implemented. Endpoint `/oidc/par` stores params and returns `request_uri`. Authorize endpoint resolves `request_uri` before processing.
3. ✅ **DPoP** — RFC 9449 implemented. Sender-constrained tokens via `cnf.jkt` binding in access tokens. Full proof verification in `crates/oidc-oidc/src/tokens/dpop.rs`: validates `typ=dpop+jwt`, `alg`, `htm`, `htu`, `iat` window, `ath` (access token hash), JWK thumbprint (RFC 7638), signature verification. Token endpoint accepts `DPoP` header and binds tokens. UserInfo endpoint validates DPoP proofs for DPoP-bound tokens. Introspection includes `cnf` claim and `token_type=DPoP`. Discovery includes `dpop_signing_alg_values_supported`.
4. ✅ **JWT Client Auth** — `private_key_jwt` implemented per RFC 7523. JWK public-key verification for RS256 and EdDSA. Wired into token, introspect, revoke, and PAR endpoints. `client_secret_jwt` ✅ — HMAC-signed JWT (HS256/HS384/HS512) with AES-256-GCM reversible secret storage. Client secret is encrypted at rest (not hashed) when `client_secret_jwt` is the auth method, enabling HMAC signature verification. Wired into all 5 client authentication endpoints (token, device, PAR, introspect, revoke). Discovery includes `token_endpoint_auth_methods_supported` and `token_endpoint_auth_signing_alg_values_supported`.

#### **Phase 3 — Session Management (Medium Priority)**
1. ❌ **Check Session Iframe** — no longer claimed as supported. The hub intentionally does not advertise `check_session_iframe`, and the endpoint returns `501 Not Implemented` until a fully interoperable implementation exists.
2. ✅ **`session_state`** — Included in authorization response (Session §3). Computed as `SHA256(client_id + " " + sid + " " + origin)` base64url where `origin` is extracted from the `redirect_uri`. Added `sid` field to `Session` model (V22 migration). `generate_sid()` utility generates 128-bit hex-encoded session IDs. `compute_session_state()` and `extract_origin()` utilities in `oidc-core/src/utils/token.rs`.
3. ✅ **Front-Channel Logout** — Cross-iframe logout notifications (Front-Channel §6). When a session is terminated, the OP renders an HTML page with invisible iframes pointing to each RP's `frontchannel_logout_uri`. Each iframe URL includes `iss` (issuer) and optionally `sid` (when `frontchannel_logout_session_required=true`). Client model includes `frontchannel_logout_uri` and `frontchannel_logout_session_required` fields.
4. ✅ **Back-Channel Logout** — Server-to-server logout notifications (Back-Channel §7). OP issues signed logout tokens (JWT with `iss`, `sub`, `aud`, `iat`, `jti`, `events`, optional `sid`) and delivers them via HTTP POST to each RP's `backchannel_logout_uri`. Uses `reqwest` on native, `wstd` HTTP client on WASI P2. Client model includes `backchannel_logout_uri` and `backchannel_logout_session_required` fields. Logout tokens signed with RS256 via `JwtTokenService::encode_logout_token()`.

**Additional changes:**
- `sid` claim added to ID tokens in all flows (authorization_code, password, refresh_token, implicit/hybrid)
- `post_logout_redirect_uris` field added to Client model (preferred over `redirect_uris` for logout redirects)
- Logout endpoint enhanced: extracts session from both `id_token_hint` and cookie, triggers front-channel and back-channel logout for all affected clients
- Discovery documents include `check_session_iframe`, `frontchannel_logout_supported`, `frontchannel_logout_session_supported`, `backchannel_logout_supported`, `backchannel_logout_session_supported`, and `sid` in `claims_supported`
- V22 migration adds `sid` column to sessions table and session management columns to clients table
- Session repository: added `find_active_by_user_id()` and `find_by_sid()` methods

#### **Phase 4 — Identity & Federation (Medium Priority)**
1. ✅ **Pairwise Subject Identifiers** — Per-sector pseudonymous `sub` values via `SHA256(user_id|sector|salt)` base64url (OIDC Core §8). Client model includes `subject_type` ("public" or "pairwise") and `sector_identifier_uri`. `compute_pairwise_sub()` and `extract_sector_identifier()` utilities in `oidc-core/src/utils/token.rs`. All token flows (authorization_code, password, refresh_token, implicit/hybrid) compute pairwise sub when client's `subject_type` is "pairwise". `pairwise_salt` on `OidcState` (from `OIDC_PAIRWISE_SALT` env var). Discovery includes `subject_types_supported: ["public", "pairwise"]`. V23 migration adds `subject_type` and `sector_identifier_uri` columns to clients table.
2. ✅ **ACR / AMR** — Authentication Context Reference and Methods References (OIDC Core §2). Dynamic ACR/AMR resolution via `resolve_acr_amr()` based on authentication method (pwd, mfa, otp, sms, device_code, token_exchange, social). Supported ACR values: `urn:mace:incommon:iap:bronze` (single-factor), `urn:mace:incommon:iap:silver` (MFA). Supported AMR values: `pwd`, `mfa`, `otp`, `sms`, `device_code`, `token_exchange`, `social`. `acr_values` parameter validated in authorization requests; returns `login_required` if requested ACR cannot be satisfied (OIDC Core §3.1.2.2). `claims_locales` parameter resolved via `resolve_locale()` for ID token `locale` claim (OIDC Core §5.2). `id_token_hint` parameter verified in authorize endpoint with `account_selection_required` error on mismatch (OIDC Core §3.1.2.2). Discovery includes `acr_values_supported`, `amr_values_supported`, `claims_locales_supported`, and `acr`/`amr` in `claims_supported`. V24 migration adds `acr_values` column; V34 migration adds `claims_locales` column to authorization_codes table.
3. ✅ **Password Reset Flow** — Self-service password reset. Two endpoints: `POST /oidc/password-reset/request` (initiate) and `POST /oidc/password-reset/confirm` (confirm). `PasswordResetToken` model with SHA-256 hash storage, 15-minute expiry, single-use. `PasswordResetTokenRepo` for DB operations. `EmailSender` trait with `send_password_reset_email()` for pluggable email delivery (default: `NoOpEmailSender`). Anti-enumeration: request endpoint always returns success. V25 migration creates `password_reset_tokens` table.
4. ✅ **Email Verification** — Token-based email verification. Two endpoints: `POST /oidc/email-verification/request` (initiate) and `POST /oidc/email-verification/confirm` (confirm). `EmailVerificationToken` model with SHA-256 hash storage, 24-hour expiry, single-use. `EmailVerificationTokenRepo` for DB operations. `EmailSender` trait with `send_email_verification()`. Anti-enumeration: request endpoint always returns success. V26 migration creates `email_verification_tokens` table.
5. ✅ **Social Login / Federation** — Upstream OIDC identity provider integration. `IdentityProvider` model with per-realm configuration (alias, issuer, authorization/token/userinfo/jwks URLs, client_id/secret, scopes, `auto_create_users`, `link_users_by_email`). `IdentityProviderType` enum (Oidc, Google, GitHub). `FederatedIdentity` model links local users to upstream subjects. Three endpoints: `GET /realms/{realm}/protocol/openid-connect/social` (list providers), `GET /realms/{realm}/protocol/openid-connect/social/{provider}` (initiate login → redirect to upstream), `GET /realms/{realm}/protocol/openid-connect/social/{provider}/callback` (callback → exchange code, fetch userinfo, create/link user, issue local tokens). HTTP client: `reqwest` on native, `wstd` on WASI P2. V27 migration creates `identity_providers` and `federated_identities` tables.

#### **Phase 5 — Extensions (Low Priority)**
1. ✅ **Device Authorization Grant** (RFC 8628) — For headless/input-constrained devices. `DeviceCode` model with SHA-256 hashed device codes, consonant-only user codes (XXXX-XXXX), 15-minute expiry. Three endpoints: `POST /oidc/device/authorize` (device code issuance), `GET /oidc/device` (verification page), `POST /oidc/device/confirm` (user authorization). Token endpoint supports `urn:ietf:params:oauth:grant-type:device_code` grant with `authorization_pending`, `slow_down`, `expired_token` errors per RFC 8628 §3.5. V28 migration creates `device_codes` table.
2. ✅ **Token Exchange** (RFC 8693) — Token delegation and impersonation. `TokenExchangeFlow` supports `subject_token_type` values: `access_token`, `refresh_token`, `id_token`. Optional `actor_token` for delegation. Issues `access_token`, `refresh_token`, or `id_token` per `requested_token_type`. Includes `issued_token_type`, `may_act`, `act` claims per RFC 8693. Confidential clients only. V29 migration not needed (uses existing tables).
3. ✅ **JWT Bearer Token** (RFC 7523 §2.1) — For client authentication and assertions. `JwtBearerFlow` accepts a signed JWT assertion from the client, verifies signature against client JWKS, issues access token for the subject. Supports `sub == iss` (client on own behalf) and `sub != iss` (delegation). No refresh or ID token issued. V29 migration not needed.
4. ✅ **JWE Encrypted ID Tokens** — For highly sensitive deployments. Supports `dir` (direct symmetric key with A256GCM) and `RSA-OAEP-256` (RSA key wrapping with A256GCM). Client model includes `id_token_encrypted_response_alg`, `id_token_encrypted_response_enc`, `id_token_encryption_key_encrypted`, `id_token_encryption_key_pem`. All ID token issuance flows (authorization_code, password, refresh_token, device_code, token_exchange, implicit/hybrid) encrypt the signed JWT if the client has encryption configured. V31 migration adds JWE columns to clients table.
5. ✅ **Encrypted Request Objects** — JWE-encrypted authorization requests per OIDC Core §10. Supports `dir` (direct symmetric key with A256GCM) and `RSA-OAEP-256` (RSA key wrapping with A256GCM). Nested JWT pattern: sign-then-encrypt. Authorize endpoint detects 5-part JWE, decrypts using client's configured encryption keys, then processes the inner signed JWT. Client model includes `request_object_encryption_alg`, `request_object_encryption_enc`, `request_object_encryption_key_encrypted`, `request_object_encryption_key_pem`. Discovery includes `request_object_encryption_alg_values_supported` and `request_object_encryption_enc_values_supported`. V39 migration adds request object encryption columns to clients table.
6. ✅ **JARM** (RFC 9101) — JWT-Secured Authorization Response Mode. Supports `query.jwt`, `fragment.jwt`, `form_post.jwt`, and `jwt` (auto-resolved based on response_type). All authorization response parameters are wrapped in a JWT signed by the OP. Client model includes `response_modes` field. V30 migration adds `response_mode` to authorization_codes and `response_modes` to clients.
7. ✅ **RAR** (RFC 9396) — Rich Authorization Requests. `AuthorizationDetail` model with `type`, `locations`, `actions`, `datatypes`, `identifier`, `privileges`, and extensible `extra` fields. `authorization_details` parameter in authorization requests, stored in auth codes and sessions, included in access token claims and introspection responses. V32 migration adds `authorization_details` JSONB column to authorization_codes and sessions.
8. ✅ **WebFinger** (RFC 7033 / OIDC Discovery §5) — OpenID Connect Discovery via webfinger. `GET /.well-known/webfinger?resource=acct:user@example.com` returns the OIDC issuer URL for the user's realm. Supports `rel` parameter filtering. V33 migration not needed (uses existing tables).

---

*Generated from audit of `crates/oidc-core`, `crates/oidc-repository`, `crates/oidc-oidc`, `crates/oidc-apikey`, `crates/oidc-migrate`, and `crates/openid-connect-wasi`.*
