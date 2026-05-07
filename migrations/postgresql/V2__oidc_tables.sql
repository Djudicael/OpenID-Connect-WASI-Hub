-- V2__oidc_tables.sql
-- Clients, sessions, and signing keys for OIDC/OAuth2.

CREATE TABLE IF NOT EXISTS clients (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    realm_id UUID NOT NULL REFERENCES realms(id),
    client_id TEXT NOT NULL UNIQUE,
    client_type TEXT NOT NULL CHECK (client_type IN ('confidential', 'public')),
    client_secret_hash TEXT,
    name TEXT NOT NULL,
    redirect_uris TEXT[] NOT NULL,
    allowed_scopes TEXT[] NOT NULL DEFAULT ARRAY['openid'],
    allowed_grant_types TEXT[] NOT NULL DEFAULT ARRAY['authorization_code'],
    pkce_required BOOLEAN NOT NULL DEFAULT TRUE,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS sessions (
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

CREATE TABLE IF NOT EXISTS signing_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    realm_id UUID NOT NULL REFERENCES realms(id),
    kid TEXT NOT NULL UNIQUE,
    algorithm TEXT NOT NULL CHECK (algorithm IN ('RS256', 'EdDSA')),
    public_key_pem TEXT NOT NULL,
    private_key_pem_encrypted TEXT,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    retired_at TIMESTAMPTZ
);
