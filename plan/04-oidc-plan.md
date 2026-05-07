# OIDC / OAuth2 Implementation Plan

Conforms to **OpenID Connect Core 1.0** and **OAuth 2.0** (RFC 6749, 7636). Production-grade security defaults.

---

## 1. Endpoints

| Method | Path | Description | Auth |
|--------|------|-------------|------|
| GET | `/.well-known/openid-configuration` | Discovery document | None |
| GET | `/oidc/jwks` | JSON Web Key Set | None |
| GET | `/oidc/authorize` | Authorization endpoint | None (redirects to login) |
| POST | `/oidc/token` | Token endpoint | Client auth |
| POST | `/oidc/introspect` | Token introspection | Client auth |
| POST | `/oidc/revoke` | Token revocation | Client auth |
| GET | `/oidc/userinfo` | UserInfo endpoint | Access token |
| POST | `/oidc/register` | Dynamic client registration | Bearer (admin) |
| GET | `/oidc/logout` | RP-initiated logout | ID token hint |

---

## 2. Discovery Document (`.well-known/openid-configuration`)

```json
{
  "issuer": "https://auth.example.com",
  "authorization_endpoint": "https://auth.example.com/oidc/authorize",
  "token_endpoint": "https://auth.example.com/oidc/token",
  "userinfo_endpoint": "https://auth.example.com/oidc/userinfo",
  "jwks_uri": "https://auth.example.com/oidc/jwks",
  "registration_endpoint": "https://auth.example.com/oidc/register",
  "scopes_supported": ["openid", "profile", "email", "phone", "address", "offline_access"],
  "response_types_supported": ["code", "token", "id_token", "code id_token", "code token", "code id_token token"],
  "grant_types_supported": ["authorization_code", "client_credentials", "refresh_token"],
  "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "private_key_jwt"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256", "EdDSA"],
  "claims_supported": ["sub", "iss", "aud", "exp", "iat", "name", "given_name", "family_name", "email", "email_verified"],
  "code_challenge_methods_supported": ["S256"],
  "end_session_endpoint": "https://auth.example.com/oidc/logout"
}
```

**Validation**:
- [ ] Document validates against OpenID Connect Discovery schema
- [ ] All URLs are absolute and HTTPS-only in production
- [ ] CORS enabled for `.well-known` endpoint

---

## 3. Authorization Code Flow + PKCE

### Step-by-Step

1. **Client Redirects User**:
   ```
   GET /oidc/authorize?
     response_type=code
     &client_id=my-app
     &redirect_uri=https://app.example.com/callback
     &scope=openid profile email
     &state=xyz123
     &code_challenge=BASE64URL(SHA256(verifier))
     &code_challenge_method=S256
   ```

2. **Server Validates**:
   - `client_id` exists and is enabled
   - `redirect_uri` matches registered URIs exactly
   - `response_type` supported
   - `scope` subset of allowed scopes
   - `code_challenge` present if client is public or `pkce_required=true`

3. **User Authentication**:
   - If no session cookie: redirect to `/admin/login` (or custom login URI)
   - After login: show consent screen (if `prompt=consent` or first time)

4. **Authorization Code Issued**:
   - Code: 128-bit random, hashed with SHA-256 in DB
   - Expiry: 60 seconds
   - Single use only

5. **Token Exchange**:
   ```
   POST /oidc/token
   grant_type=authorization_code
   &code=AUTH_CODE
   &redirect_uri=https://app.example.com/callback
   &client_id=my-app
   &code_verifier=PLAINTEXT_VERIFIER
   ```

6. **Server Validates**:
   - Code hash matches DB
   - `code_verifier` SHA256 matches stored `code_challenge`
   - `redirect_uri` identical to authorize request
   - Code not expired, not used before

7. **Tokens Issued**:
   - Access Token (JWT or opaque)
   - ID Token (JWT)
   - Refresh Token (opaque)

### Request Validation Checklist
- [ ] All required parameters present
- [ ] `client_id` valid and enabled
- [ ] `redirect_uri` exact match (no partial matching)
- [ ] `scope` contains `openid` for OIDC
- [ ] `state` preserved (CSRF protection)
- [ ] `nonce` included in ID token if provided
- [ ] PKCE `code_challenge` 43-128 chars, method `S256`
- [ ] `prompt=none` returns error if not logged in
- [ ] `max_age` enforces re-authentication

---

## 4. Token Formats

### Access Token (JWT Option)
```json
{
  "iss": "https://auth.example.com",
  "sub": "user-uuid",
  "aud": "my-app",
  "exp": 1715097600,
  "iat": 1715096700,
  "jti": "token-uuid",
  "scope": "openid profile",
  "realm_id": "realm-uuid"
}
```
- Signing: RS256 or EdDSA
- Key ID (`kid`) in header
- `exp`: 15 minutes default

### ID Token
```json
{
  "iss": "https://auth.example.com",
  "sub": "user-uuid",
  "aud": "my-app",
  "exp": 1715100300,
  "iat": 1715096700,
  "auth_time": 1715096700,
  "nonce": "client-nonce",
  "email": "user@example.com",
  "email_verified": true,
  "name": "John Doe",
  "given_name": "John",
  "family_name": "Doe"
}
```
- Signing: Same key as access token
- `nonce` mandatory if provided in auth request
- `at_hash`, `c_hash` included for hybrid flow

### Refresh Token
- Opaque: 256-bit random, base64url-encoded
- Stored as SHA-256 hash in `sessions.refresh_token_hash`
- Rotation: New refresh token issued on every use; old one invalidated
- Family detection: If rotated token is reused, entire family revoked (token theft detection)

---

## 5. Client Authentication at Token Endpoint

Supported methods:
1. `client_secret_basic`: `Authorization: Basic BASE64(client_id:client_secret)`
2. `client_secret_post`: `client_id` and `client_secret` in request body
3. `private_key_jwt`: JWT signed by client's private key (optional, phase 2)

**Validation**:
- [ ] Secret compared with Argon2id hash (not plaintext)
- [ ] Constant-time comparison to prevent timing attacks
- [ ] Reject if client is public and tries `client_secret_basic`

---

## 6. Token Introspection (RFC 7662)

```
POST /oidc/introspect
Authorization: Basic ...
token=<access_token>
```

Response:
```json
{
  "active": true,
  "scope": "openid profile",
  "client_id": "my-app",
  "username": "john.doe",
  "token_type": "Bearer",
  "exp": 1715097600,
  "iat": 1715096700,
  "sub": "user-uuid"
}
```

- [ ] Active tokens return full claims
- [ ] Inactive/revoked tokens return `{"active": false}`
- [ ] Confidential clients can only introspect their own tokens

---

## 7. Token Revocation (RFC 7009)

```
POST /oidc/revoke
Authorization: Basic ...
token=<token>
```

- [ ] Access token revoked immediately
- [ ] Refresh token revoked; all tokens in family revoked if rotation enabled
- [ ] Idempotent: revoking already revoked token returns 200

---

## 8. UserInfo Endpoint

```
GET /oidc/userinfo
Authorization: Bearer <access_token>
```

Response:
```json
{
  "sub": "user-uuid",
  "name": "John Doe",
  "given_name": "John",
  "family_name": "Doe",
  "email": "user@example.com",
  "email_verified": true
}
```

- [ ] Returns claims based on `scope` from access token
- [ ] Signed JWT response supported (`application/jwt` Accept header)
- [ ] CORS enabled for SPAs

---

## 9. Logout

### RP-Initiated Logout
```
GET /oidc/logout?
  id_token_hint=<id_token>
  &post_logout_redirect_uri=https://app.example.com/logged-out
  &state=abc
```

- [ ] `id_token_hint` validated (signature, issuer, audience)
- [ ] `post_logout_redirect_uri` matches registered logout URIs
- [ ] Session cookie cleared
- [ ] All tokens for session marked revoked in DB
- [ ] Redirects to `post_logout_redirect_uri` with `state`

---

## 10. Session Management (Optional)

- **Session Cookie**: `__Host-session` (HttpOnly, Secure, SameSite=Lax)
- **Session State**: `session_state` hash included in auth response for OP iframe check
- **Check Session Iframe**: `GET /oidc/check_session` (optional, phase 2)

---

## 11. Error Responses

All errors return `400 Bad Request` or `401 Unauthorized` with:
```json
{
  "error": "invalid_request",
  "error_description": "The request is missing a required parameter...",
  "state": "xyz123"
}
```

Standard `error` values:
- `invalid_request`
- `invalid_client`
- `invalid_grant`
- `unauthorized_client`
- `unsupported_grant_type`
- `invalid_scope`
- `access_denied`
- `server_error`

---

## 12. Checklist

- [ ] Discovery endpoint returns complete, valid document
- [ ] JWKS endpoint exposes public keys with correct `kid`, `alg`, `use`
- [ ] Authorization Code flow works end-to-end with PKCE
- [ ] Token endpoint accepts `client_secret_basic` and `client_secret_post`
- [ ] Access token validates via JWKS (signature, expiry, issuer, audience)
- [ ] Refresh token rotation works; reuse detection revokes family
- [ ] Introspection returns correct `active` status
- [ ] Revocation makes tokens inactive immediately
- [ ] UserInfo returns claims scoped to access token
- [ ] Logout clears session and redirects correctly
- [ ] All error responses conform to OAuth2 JSON error format
- [ ] Conformance test suite passes (https://www.certification.openid.net/)
- [ ] WASM build includes OIDC endpoints without filesystem dependencies
