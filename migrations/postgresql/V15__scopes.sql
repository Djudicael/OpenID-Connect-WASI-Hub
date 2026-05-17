-- V15__scopes.sql
-- Finalized scopes and realm signing keys schema.

CREATE TABLE IF NOT EXISTS scopes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    realm_id UUID NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    description TEXT,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(realm_id, name)
);

CREATE INDEX IF NOT EXISTS idx_scopes_realm ON scopes(realm_id);

CREATE TABLE IF NOT EXISTS client_scopes (
    client_id UUID NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    scope_id UUID NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
    PRIMARY KEY (client_id, scope_id)
);

CREATE INDEX IF NOT EXISTS idx_client_scopes_scope ON client_scopes(scope_id);

CREATE TABLE IF NOT EXISTS realm_signing_keys (
    realm_id UUID PRIMARY KEY REFERENCES realms(id) ON DELETE CASCADE,
    rsa_private_pem TEXT NOT NULL,
    rsa_kid VARCHAR(64) NOT NULL DEFAULT 'key-1',
    rsa_public_n TEXT NOT NULL,
    rsa_public_e TEXT NOT NULL,
    ed25519_private_pem TEXT NOT NULL,
    ed25519_kid VARCHAR(64) NOT NULL DEFAULT 'ed-key-1',
    ed25519_public_x TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
