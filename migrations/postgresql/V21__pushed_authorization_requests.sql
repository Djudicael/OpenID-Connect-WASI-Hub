-- V21__pushed_authorization_requests.sql
-- Finalized PAR and Device Authorization Grant schema.

CREATE TABLE IF NOT EXISTS pushed_authorization_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id UUID NOT NULL REFERENCES clients(id),
    realm_id UUID NOT NULL REFERENCES realms(id),
    request_uri_token TEXT NOT NULL UNIQUE,
    request_params JSONB NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_par_token ON pushed_authorization_requests(request_uri_token);
CREATE INDEX IF NOT EXISTS idx_par_expires ON pushed_authorization_requests(expires_at);

CREATE TABLE IF NOT EXISTS device_codes (
    id UUID PRIMARY KEY,
    client_id UUID NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    realm_id UUID NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    device_code_hash VARCHAR(64) NOT NULL,
    user_code VARCHAR(9) NOT NULL,
    verification_uri TEXT NOT NULL,
    verification_uri_complete TEXT,
    expires_at TIMESTAMPTZ NOT NULL,
    interval_seconds INT NOT NULL DEFAULT 5,
    used BOOLEAN NOT NULL DEFAULT FALSE,
    authorized BOOLEAN NOT NULL DEFAULT FALSE,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    scope JSONB NOT NULL DEFAULT '[]',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_device_codes_device_code_hash ON device_codes(device_code_hash);
CREATE INDEX IF NOT EXISTS idx_device_codes_user_code ON device_codes(user_code);
CREATE INDEX IF NOT EXISTS idx_device_codes_expires_at ON device_codes(expires_at);
