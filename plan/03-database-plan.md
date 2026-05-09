# Database & PostgreSQL Integration Plan

Uses `pg_client` (https://github.com/Djudicael/pg_client) as the exclusive PostgreSQL driver. First-class WASI P2 support with native fallback for testing.

---

## 1. Schema Design (Production-Grade)

### Naming Conventions
- Tables: plural, snake_case (`users`, `api_keys`, `signing_keys`)
- Columns: snake_case (`created_at`, `hashed_secret`)
- Primary keys: `id UUID` (UUID v7)
- Foreign keys: `<table>_id`
- Timestamps: `TIMESTAMPTZ` (not `TIMESTAMP`)
- Soft deletes: `deleted_at TIMESTAMPTZ NULL` (no hard deletes on user data)

### Core Tables

#### `realms`
```sql
CREATE TABLE realms (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    config JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

#### `users`
```sql
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    realm_id UUID NOT NULL REFERENCES realms(id),
    email TEXT NOT NULL,
    email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    username TEXT,
    password_hash TEXT,              -- NULL for federated / API-only users
    given_name TEXT,
    family_name TEXT,
    phone_number TEXT,
    locale TEXT DEFAULT 'en',
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    attributes JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ,
    UNIQUE(realm_id, email)
);
CREATE INDEX idx_users_realm_email ON users(realm_id, email) WHERE deleted_at IS NULL;
```

#### `clients`
```sql
CREATE TABLE clients (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    realm_id UUID NOT NULL REFERENCES realms(id),
    client_id TEXT NOT NULL UNIQUE,
    client_type TEXT NOT NULL CHECK (client_type IN ('confidential', 'public')),
    client_secret_hash TEXT,         -- NULL for public clients
    name TEXT NOT NULL,
    redirect_uris TEXT[] NOT NULL,
    allowed_scopes TEXT[] NOT NULL DEFAULT ARRAY['openid'],
    allowed_grant_types TEXT[] NOT NULL DEFAULT ARRAY['authorization_code'],
    pkce_required BOOLEAN NOT NULL DEFAULT TRUE,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

#### `sessions`
```sql
CREATE TABLE sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id),
    realm_id UUID NOT NULL REFERENCES realms(id),
    client_id UUID NOT NULL REFERENCES clients(id),
    grant_type TEXT NOT NULL,
    access_token_hash TEXT NOT NULL,
    refresh_token_hash TEXT,
    id_token_jti TEXT,
    scope TEXT[] NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    refresh_expires_at TIMESTAMPTZ,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ
);
CREATE INDEX idx_sessions_access_hash ON sessions(access_token_hash);
CREATE INDEX idx_sessions_refresh_hash ON sessions(refresh_token_hash);
CREATE INDEX idx_sessions_expires ON sessions(expires_at) WHERE NOT revoked;
```

#### `api_keys`
```sql
CREATE TABLE api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    realm_id UUID NOT NULL REFERENCES realms(id),
    name TEXT NOT NULL,
    prefix TEXT NOT NULL,            -- First 8 chars of key for display
    hashed_secret TEXT NOT NULL,     -- Argon2id or HMAC-SHA256
    scopes TEXT[] NOT NULL DEFAULT ARRAY[],
    expires_at TIMESTAMPTZ,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    last_used_at TIMESTAMPTZ,
    request_count BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by UUID REFERENCES users(id)
);
CREATE INDEX idx_api_keys_prefix ON api_keys(prefix);
CREATE INDEX idx_api_keys_realm ON api_keys(realm_id) WHERE NOT revoked;
```

#### `signing_keys`
```sql
CREATE TABLE signing_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    realm_id UUID NOT NULL REFERENCES realms(id),
    kid TEXT NOT NULL UNIQUE,        -- Key ID for JWKS
    algorithm TEXT NOT NULL CHECK (algorithm IN ('RS256', 'EdDSA')),
    public_key_pem TEXT NOT NULL,
    private_key_pem_encrypted TEXT,  -- AES-256-GCM encrypted; NULL for HSM-backed
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    retired_at TIMESTAMPTZ
);
```

### Audit / Events Table
```sql
CREATE TABLE audit_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    realm_id UUID REFERENCES realms(id),
    event_type TEXT NOT NULL,
    actor_id UUID REFERENCES users(id),
    actor_type TEXT NOT NULL CHECK (actor_type IN ('user', 'api_key', 'system')),
    target_type TEXT,
    target_id UUID,
    details JSONB NOT NULL DEFAULT '{}',
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_audit_realm_time ON audit_events(realm_id, created_at);
CREATE INDEX idx_audit_actor ON audit_events(actor_id, created_at);
```

---

## 2. Migration Strategy

### Tooling
- **Native**: `refinery` or custom CLI `oidc-migrate` using `tokio-postgres`.
- **WASM**: Migrations run **before** deployment in an init container or CI step. The WASM binary assumes a pre-migrated schema.

### Migration Files
```
migrations/postgresql/
├── V1__init.sql
├── V2__oidc_tables.sql
├── V3__api_keys.sql
├── V4__audit_events.sql
└── V5__indexes.sql
```

Each migration must be:
- Idempotent where possible (`IF NOT EXISTS`)
- Wrapped in a transaction
- Tested against PostgreSQL 15, 16, 17

**Validation Criteria**:
- [ ] Migrations apply cleanly on empty database
- [ ] Migrations are backward-compatible (no destructive schema changes in minor versions)
- [ ] Rollback scripts provided for each migration (manual, tested)
- [ ] Migration checksums verified in CI

---

## 3. pg_client Integration

### Connection Config
```rust
use wasi_pg_client::{Config, Connection};

pub async fn connect_wasi(database_url: &str) -> Result<Connection, PgError> {
    let config = Config::from_uri(database_url)?;
    Connection::connect(config).await
}
```

### Pool Config (WASM)
```rust
use wasi_pg_pool::{Pool, PoolConfig};

pub async fn create_pool(database_url: &str, max_size: u32) -> Result<Pool, PgError> {
    let config = Config::from_uri(database_url)?;
    let pool_config = PoolConfig::default()
        .connection(config)
        .max_size(max_size);
    Pool::new(pool_config).await
}
```

### Native Fallback (for tests)
```rust
#[cfg(not(target_arch = "wasm32"))]
pub async fn connect_native(database_url: &str) -> Result<tokio_postgres::Client, Error> {
    let (client, connection) = tokio_postgres::connect(database_url, tokio_postgres::NoTls).await?;
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            tracing::error!("postgres connection error: {}", e);
        }
    });
    Ok(client)
}
```

### Repository Pattern Example
```rust
pub struct UserRepository<T> {
    connection: T,
}

#[async_trait::async_trait]
impl Repository<User> for UserRepository<Connection> {
    async fn find_by_id(&self, id: Uuid) -> Result<Option<User>, Error> {
        let result = self.connection
            .query_params(
                "SELECT id, realm_id, email, email_verified, username, password_hash,
                        given_name, family_name, enabled, attributes, created_at
                 FROM users WHERE id = $1 AND deleted_at IS NULL",
                &[&id],
            )
            .await?;
        
        result.iter().next().map(|row| {
            Ok(User {
                id: row.get(0)?,
                realm_id: row.get(1)?,
                email: row.get(2)?,
                // ...
            })
        }).transpose()
    }
}
```

---

## 4. Performance & Operations

### Indexes (Explicit)
All indexes defined in `V6__indexes.sql`:
- `users`: `(realm_id, email)`, `(created_at)`
- `sessions`: `(access_token_hash)`, `(refresh_token_hash)`, `(expires_at)`
- `api_keys`: `(prefix)`, `(realm_id, revoked)`
- `audit_events`: `(realm_id, created_at)`, `(actor_id, created_at)`


### Connection Tuning
| Parameter | WASM | Native | Rationale |
|-----------|------|--------|-----------|
| max_size | 5 | 20 | WASM single-threaded; fewer connections needed |
| acquire_timeout | 5s | 5s | Fail fast |
| idle_timeout | 600s | 600s | PostgreSQL default |
| max_lifetime | 3600s | 3600s | Rotate connections hourly |

### Query Guidelines
- Every query must be parameterized (`$1`, `$2`).
- No `SELECT *` in production code.
- Use `FOR UPDATE` when updating sessions (prevent race conditions on token refresh).
- Batch inserts for audit events (if volume > 100/s, use `COPY` or async queue).

---

## 5. Data Integrity & Constraints

- **Foreign Keys**: Enforced at DB level (not application level).
- **Check Constraints**: `client_type`, `algorithm`, `actor_type` enums.
- **Unique Constraints**: `realms.name`, `clients.client_id`, `users(realm_id, email)`, `signing_keys.kid`.
- **Soft Deletes**: `deleted_at` on `users`; never `DELETE FROM users`.
- **Cascade Rules**: `ON DELETE CASCADE` only on `sessions`, `api_keys` (link to user); `RESTRICT` on `realms`.

---

## 6. Backup & Disaster Recovery

- **Strategy**: `pg_dump` native tool (cannot run in WASM).
- **Frequency**: Daily full, hourly WAL archiving.
- **Test**: Monthly restore test in staging environment.
- **Encryption**: Backup files encrypted at rest (AES-256).

---

## 7. Checklist

- [ ] Schema SQL written and reviewed
- [ ] Migration files created (`V1` through `V5`)
- [ ] `oidc-repository` crate connects with `pg_client` on WASM
- [ ] `oidc-repository` crate connects with `tokio-postgres` on native
- [ ] All queries parameterized; no string interpolation
- [ ] Indexes created and `EXPLAIN ANALYZE` verified on representative data (1M users, 10M sessions)
- [ ] Soft delete logic implemented in all repositories
- [ ] Audit event insertion ≤ 10ms p99
- [ ] Connection pool stress test (2x max_size concurrent requests)
- [ ] Migration rollback tested
- [ ] Native integration tests pass with real PostgreSQL
