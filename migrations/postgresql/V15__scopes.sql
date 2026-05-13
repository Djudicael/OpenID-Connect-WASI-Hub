-- V15__scopes.sql
-- Realm-scoped scopes with client-scope mapping.

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
