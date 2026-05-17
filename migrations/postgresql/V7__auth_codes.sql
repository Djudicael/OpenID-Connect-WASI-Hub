-- V7__auth_codes.sql
-- Finalized authorization code schema for Authorization Code + PKCE and OIDC extensions.

CREATE TABLE IF NOT EXISTS authorization_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code TEXT NOT NULL UNIQUE,
    client_id UUID NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    realm_id UUID NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    redirect_uri TEXT NOT NULL,
    scope JSONB NOT NULL DEFAULT '[]',
    code_challenge TEXT NOT NULL,
    code_challenge_method TEXT NOT NULL DEFAULT 'S256',
    nonce TEXT,
    used BOOLEAN NOT NULL DEFAULT FALSE,
    claims_request JSONB,
    display TEXT,
    response_type TEXT NOT NULL DEFAULT 'code',
    acr_values JSONB DEFAULT '[]',
    claims_locales JSONB NOT NULL DEFAULT '[]',
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    response_mode VARCHAR(20),
    authorization_details JSONB,
    resource JSONB NOT NULL DEFAULT '[]'
);

CREATE INDEX IF NOT EXISTS idx_auth_codes_code ON authorization_codes(code) WHERE NOT used;
CREATE INDEX IF NOT EXISTS idx_auth_codes_expires ON authorization_codes(expires_at) WHERE NOT used;
CREATE INDEX IF NOT EXISTS idx_auth_codes_cleanup ON authorization_codes(expires_at);
