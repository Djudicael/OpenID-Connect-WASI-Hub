-- V2__oidc_tables.sql
-- Finalized OIDC/OAuth2 runtime tables: clients, sessions, and signing keys.

CREATE TABLE IF NOT EXISTS clients (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    realm_id UUID NOT NULL REFERENCES realms(id),
    client_id TEXT NOT NULL UNIQUE,
    client_type TEXT NOT NULL CHECK (client_type IN ('confidential', 'public')),
    client_secret_hash TEXT,
    name TEXT NOT NULL,
    redirect_uris JSONB NOT NULL DEFAULT '[]',
    allowed_scopes JSONB NOT NULL DEFAULT '["openid"]',
    allowed_grant_types JSONB NOT NULL DEFAULT '["authorization_code"]',
    pkce_required BOOLEAN NOT NULL DEFAULT TRUE,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    deleted_at TIMESTAMPTZ,
    token_endpoint_auth_method TEXT NOT NULL DEFAULT 'client_secret_basic'
        CHECK (token_endpoint_auth_method IN ('none', 'client_secret_basic', 'client_secret_post', 'client_secret_jwt', 'private_key_jwt')),
    jwks_uri TEXT,
    jwks JSONB,
    request_uris JSONB NOT NULL DEFAULT '[]',
    client_secret_encrypted TEXT,
    frontchannel_logout_uri TEXT,
    frontchannel_logout_session_required BOOLEAN NOT NULL DEFAULT FALSE,
    backchannel_logout_uri TEXT,
    backchannel_logout_session_required BOOLEAN NOT NULL DEFAULT FALSE,
    post_logout_redirect_uris JSONB NOT NULL DEFAULT '[]',
    subject_type TEXT NOT NULL DEFAULT 'public',
    sector_identifier_uri TEXT,
    response_modes JSONB NOT NULL DEFAULT '["query", "fragment"]',
    id_token_encrypted_response_alg VARCHAR(20),
    id_token_encrypted_response_enc VARCHAR(10),
    id_token_encryption_key_encrypted TEXT,
    id_token_encryption_key_pem TEXT,
    request_object_encryption_alg TEXT,
    request_object_encryption_enc TEXT DEFAULT 'A256GCM',
    request_object_encryption_key_encrypted TEXT,
    request_object_encryption_key_pem TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_clients_deleted_at
    ON clients(deleted_at)
    WHERE deleted_at IS NOT NULL;

CREATE TABLE IF NOT EXISTS sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sid TEXT NOT NULL DEFAULT encode(gen_random_bytes(16), 'hex'),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    realm_id UUID NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    client_id UUID NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    grant_type TEXT NOT NULL,
    access_token_hash TEXT NOT NULL,
    refresh_token_hash TEXT,
    id_token_jti TEXT,
    scope JSONB NOT NULL DEFAULT '[]',
    expires_at TIMESTAMPTZ NOT NULL,
    refresh_expires_at TIMESTAMPTZ,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,
    token_family_id UUID,
    previous_session_id UUID,
    rotated_at TIMESTAMPTZ,
    reused_at TIMESTAMPTZ,
    family_revoked BOOLEAN NOT NULL DEFAULT FALSE,
    authorization_details JSONB,
    resource JSONB NOT NULL DEFAULT '[]'
);

CREATE INDEX IF NOT EXISTS idx_sessions_access_hash ON sessions(access_token_hash);
CREATE INDEX IF NOT EXISTS idx_sessions_refresh_hash ON sessions(refresh_token_hash);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at) WHERE NOT revoked;
CREATE INDEX IF NOT EXISTS idx_sessions_cleanup ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_sessions_realm_id ON sessions(realm_id);
CREATE INDEX IF NOT EXISTS idx_sessions_sid ON sessions(sid);
CREATE INDEX IF NOT EXISTS idx_sessions_token_family ON sessions(token_family_id);
CREATE INDEX IF NOT EXISTS idx_sessions_previous ON sessions(previous_session_id);

CREATE TABLE IF NOT EXISTS signing_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    realm_id UUID NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    kid TEXT NOT NULL UNIQUE,
    algorithm TEXT NOT NULL CHECK (algorithm IN ('RS256', 'EdDSA')),
    public_key_pem TEXT NOT NULL,
    private_key_pem_encrypted TEXT,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    retired_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_signing_keys_realm_id ON signing_keys(realm_id);
