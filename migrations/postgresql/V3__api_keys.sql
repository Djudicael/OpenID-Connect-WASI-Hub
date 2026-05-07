-- V3__api_keys.sql
-- API key management for machine-to-machine authentication.

CREATE TABLE IF NOT EXISTS api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    realm_id UUID NOT NULL REFERENCES realms(id),
    name TEXT NOT NULL,
    prefix TEXT NOT NULL,
    hashed_secret TEXT NOT NULL,
    scopes TEXT[] NOT NULL DEFAULT ARRAY[],
    expires_at TIMESTAMPTZ,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    last_used_at TIMESTAMPTZ,
    request_count BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by UUID REFERENCES users(id)
);
