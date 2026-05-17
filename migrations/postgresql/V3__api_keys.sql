-- V3__api_keys.sql
-- Finalized API key schema for machine-to-machine authentication.

CREATE TABLE IF NOT EXISTS api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    realm_id UUID NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    prefix TEXT NOT NULL,
    hashed_secret TEXT NOT NULL,
    scopes JSONB NOT NULL DEFAULT '[]',
    expires_at TIMESTAMPTZ,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    rotated_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    request_count BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by UUID REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_api_keys_prefix ON api_keys(prefix);
CREATE INDEX IF NOT EXISTS idx_api_keys_realm ON api_keys(realm_id) WHERE NOT revoked;
CREATE INDEX IF NOT EXISTS idx_api_keys_created_by ON api_keys(created_by);
