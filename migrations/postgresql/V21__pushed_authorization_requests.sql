-- V21__pushed_authorization_requests.sql
-- Create pushed_authorization_requests table for PAR (RFC 9126).

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

CREATE INDEX idx_par_token ON pushed_authorization_requests(request_uri_token);
CREATE INDEX idx_par_expires ON pushed_authorization_requests(expires_at);
