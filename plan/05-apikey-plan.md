# API Key Management Plan

First-class API keys for service-to-service authentication, machine-to-machine access, and proxy gateway integration.

---

## 1. Overview

API Keys complement OIDC sessions by providing long-lived, revocable credentials for non-interactive clients. They are scoped, auditable, and support rotation.

---

## 2. Data Model

```rust
pub struct ApiKey {
    pub id: Uuid,
    pub realm_id: Uuid,
    pub name: String,
    pub prefix: String,            // e.g., "oidc_prod_abc1"
    pub hashed_secret: String,     // Argon2id hash of secret portion
    pub scopes: Vec<String>,       // e.g., ["users:read", "realms:write"]
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked: bool,
    pub last_used_at: Option<DateTime<Utc>>,
    pub request_count: i64,
    pub created_at: DateTime<Utc>,
    pub created_by: Option<Uuid>,
}

pub struct ApiKeyCreation {
    pub name: String,
    pub scopes: Vec<String>,
    pub expires_in_days: Option<u32>,
}

pub struct ApiKeyRaw {
    pub id: Uuid,
    pub raw_key: String,           // ONLY returned at creation
    pub api_key: ApiKey,
}
```

---

## 3. Key Format

```
oidc_<environment>_<prefix>_<random>
```

Example:
```
odc_prod_a3f9k2m9_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

- `oidc_`: Fixed prefix for identification.
- `prod_`: Environment segment (configurable).
- `a3f9k2m9`: 8-character prefix stored in plaintext for UI display and fast lookup.
- `xxxxxxxx...`: 48-character cryptographically random secret (base64url).

**Storage**:
- Only the **8-char prefix** and **Argon2id hash** of the secret are stored.
- The raw key is **shown exactly once** at creation and never again.

---

## 4. Generation Algorithm

```rust
use getrandom::getrandom;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

fn generate_api_key(environment: &str) -> (String, String) {
    let mut random_bytes = [0u8; 36]; // 48 chars base64url
    getrandom(&mut random_bytes).expect("CSPRNG failure");
    
    let secret = URL_SAFE_NO_PAD.encode(&random_bytes);
    let prefix = &secret[..8];
    
    let full_key = format!("oidc_{environment}_{prefix}_{secret}");
    (full_key, prefix.to_string())
}

fn hash_secret(secret: &str) -> String {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    argon2.hash_password(secret.as_bytes(), &salt)
        .expect("hash failure")
        .to_string()
}
```

**Validation Criteria**:
- [ ] Key entropy ≥ 256 bits (36 bytes → 48 base64url chars)
- [ ] `getrandom` works in WASM (`wasi` feature enabled)
- [ ] Argon2id params: memory=64MB, iterations=3, parallelism=1 (tuned for < 10ms verify)

---

## 5. Verification Algorithm

```rust
pub async fn verify_api_key(
    pool: &PgPool,
    raw_key: &str,
) -> Result<ApiKey, ApiKeyError> {
    // 1. Parse prefix
    let prefix = extract_prefix(raw_key)?;
    
    // 2. Lookup by prefix (fast, index-backed)
    let candidates = repo.find_by_prefix(prefix).await?;
    
    // 3. Constant-time hash comparison
    for candidate in candidates {
        if !candidate.revoked && !candidate.is_expired() {
            let parsed_hash = PasswordHash::new(&candidate.hashed_secret)?;
            if Argon2::default().verify_password(secret_part.as_bytes(), &parsed_hash).is_ok() {
                // Update last_used_at asynchronously (fire-and-forget)
                repo.touch(candidate.id).await.ok();
                return Ok(candidate);
            }
        }
    }
    
    Err(ApiKeyError::InvalidKey)
}
```

**Validation Criteria**:
- [ ] Verification time ~constant regardless of key existence (prevent timing attacks)
- [ ] Expired keys rejected
- [ ] Revoked keys rejected
- [ ] `last_used_at` updated (best effort, non-blocking)

---

## 6. HTTP Integration (Axum Middleware)

### Extractor
```rust
pub struct ApiKeyAuth(pub ApiKey);

#[async_trait]
impl<S> FromRequestParts<S> for ApiKeyAuth {
    type Rejection = ApiKeyError;
    
    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let header = parts.headers
            .get("X-API-Key")
            .or_else(|| parts.headers.get("Authorization"))
            .ok_or(ApiKeyError::Missing)?;
        
        let raw = extract_key_from_header(header)?;
        let app_state = parts.extensions.get::<AppState>().unwrap();
        let api_key = verify_api_key(&app_state.pool, &raw).await?;
        
        Ok(ApiKeyAuth(api_key))
    }
}
```

### Header Formats Supported
1. `X-API-Key: oidc_prod_abc1_xxxxxxxx...`
2. `Authorization: Bearer oidc_prod_abc1_xxxxxxxx...`

### Scope Guard
```rust
pub fn require_scope(scope: &str) -> impl Fn(&ApiKey) -> bool + Clone {
    let scope = scope.to_string();
    move |key| key.scopes.contains(&scope) || key.scopes.contains(&"*".to_string())
}
```

**Validation Criteria**:
- [ ] Extractor works in both native and WASM builds
- [ ] Missing key returns 401 with `WWW-Authenticate: Bearer`
- [ ] Invalid key returns 401 (not 403; 403 is for valid key lacking scope)
- [ ] Scope check returns 403 with `insufficient_scope` if missing

---

## 7. Endpoints

### Create API Key
```
POST /api/keys
Authorization: Bearer <admin_access_token>
Content-Type: application/json

{
  "name": "Production Service",
  "scopes": ["users:read", "sessions:read"],
  "expires_in_days": 90
}
```

Response (201 Created):
```json
{
  "id": "uuid",
  "name": "Production Service",
  "prefix": "oidc_prod_a3f9k2m9",
  "raw_key": "oidc_prod_a3f9k2m9_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
  "scopes": ["users:read", "sessions:read"],
  "expires_at": "2025-08-05T00:00:00Z",
  "created_at": "2025-05-07T00:00:00Z"
}
```

### List API Keys
```
GET /api/keys?realm_id=xxx&include_revoked=false
Authorization: Bearer <admin_access_token>
```

Response:
```json
{
  "items": [
    {
      "id": "uuid",
      "name": "Production Service",
      "prefix": "oidc_prod_a3f9k2m9",
      "scopes": ["users:read"],
      "expires_at": "2025-08-05T00:00:00Z",
      "last_used_at": "2025-05-07T12:00:00Z",
      "request_count": 1523,
      "revoked": false
    }
  ],
  "total": 1
}
```

### Revoke API Key
```
DELETE /api/keys/{id}
Authorization: Bearer <admin_access_token>
```

Response: 204 No Content

### Rotate API Key
```
POST /api/keys/{id}/rotate
Authorization: Bearer <admin_access_token>
```

Response (201 Created):
```json
{
  "id": "uuid",
  "raw_key": "oidc_prod_b4g0l3n0_yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy",
  "expires_at": "..."
}
```

- Old key has 24-hour grace period (still valid but marked `rotated`).
- New key immediately active.

**Validation Criteria**:
- [ ] Only realm admins can create/list/revoke keys in their realm
- [ ] `raw_key` never returned after creation
- [ ] Revoked key immediately rejected (no caching lag)
- [ ] Rotation preserves scopes and name
- [ ] Grace period configurable (default 24h)

---

## 8. Proxy Gateway Integration

The API gateway (deployed in `Wasm-Cloud-Platform`) validates API keys at the edge:

```
┌─────────────┐      ┌──────────────────┐      ┌─────────────────┐
│   Client    │ ──►  │  Proxy Gateway   │ ──►  │  OIDC WASI App  │
│             │      │  (key validation)│      │                 │
└─────────────┘      └──────────────────┘      └─────────────────┘
```

### Gateway Behavior
1. Extract `X-API-Key` or `Authorization: Bearer` header.
2. Call `POST /oidc/introspect` or validate JWT locally if self-contained.
3. Add `X-User-Id`, `X-Realm-Id`, `X-Scopes` headers to upstream request.
4. Strip `X-API-Key` before forwarding (defense in depth).

**Validation Criteria**:
- [ ] Gateway strips raw API key before upstream
- [ ] Upstream trusts `X-*` headers only from gateway IP range
- [ ] Fallback to direct validation if gateway unavailable

---

## 9. Rate Limiting & Quotas

| Tier | Requests/Minute | Concurrent | Notes |
|------|-----------------|------------|-------|
| Default | 100 | 10 | Per API key |
| Elevated | 10,000 | 100 | Configurable per key |

Storage: In-memory `dashmap` or Redis (native only). WASM uses lazy DB checks.

---

## 10. Checklist

- [ ] Key generation uses CSPRNG (`getrandom` with `wasi` feature)
- [ ] Key format documented and validated with regex
- [ ] Argon2id hashing with tuned parameters
- [ ] Constant-time verification
- [ ] Prefix lookup index in PostgreSQL
- [ ] Raw key shown only once at creation
- [ ] `X-API-Key` and `Authorization: Bearer` headers supported
- [ ] Axum extractor works in native and WASM
- [ ] Scope-based authorization enforced
- [ ] CRUD endpoints implemented and tested
- [ ] Rotation with grace period works
- [ ] Revocation immediate (no cache delay)
- [ ] Audit events logged for create/revoke/rotate
- [ ] Rate limiting configurable per key
- [ ] Gateway integration headers documented
