-- Device Authorization Grant (RFC 8628)
CREATE TABLE device_codes (
    id UUID PRIMARY KEY,
    client_id UUID NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    realm_id UUID NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    device_code_hash VARCHAR(64) NOT NULL,
    user_code VARCHAR(9) NOT NULL,  -- "XXXX-XXXX"
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
CREATE INDEX idx_device_codes_device_code_hash ON device_codes(device_code_hash);
CREATE INDEX idx_device_codes_user_code ON device_codes(user_code);
CREATE INDEX idx_device_codes_expires_at ON device_codes(expires_at);
