-- OpenID Connect Client-Initiated Backchannel Authentication (CIBA Core 1.0).

CREATE TABLE ciba_client_configs (
    client_id UUID PRIMARY KEY REFERENCES clients(id) ON DELETE CASCADE,
    delivery_mode TEXT NOT NULL DEFAULT 'poll' CHECK (delivery_mode IN ('poll', 'ping')),
    client_notification_endpoint TEXT,
    request_lifetime_seconds INTEGER NOT NULL DEFAULT 300 CHECK (request_lifetime_seconds BETWEEN 60 AND 900),
    polling_interval_seconds INTEGER NOT NULL DEFAULT 5 CHECK (polling_interval_seconds BETWEEN 2 AND 60),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (delivery_mode = 'poll' OR client_notification_endpoint IS NOT NULL)
);

CREATE TABLE ciba_authentication_requests (
    id UUID PRIMARY KEY,
    auth_req_id_hash TEXT NOT NULL UNIQUE,
    auth_req_id_encrypted TEXT NOT NULL,
    client_id UUID NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    realm_id UUID NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    scope JSONB NOT NULL DEFAULT '["openid"]',
    binding_message TEXT,
    request_context TEXT,
    client_notification_token_encrypted TEXT,
    delivery_mode TEXT NOT NULL CHECK (delivery_mode IN ('poll', 'ping')),
    client_notification_endpoint TEXT,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'denied', 'consumed', 'expired')),
    interval_seconds INTEGER NOT NULL DEFAULT 5,
    last_polled_at TIMESTAMPTZ,
    requested_acr JSONB NOT NULL DEFAULT '[]',
    auth_time TIMESTAMPTZ,
    acr TEXT,
    amr JSONB NOT NULL DEFAULT '[]',
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_ciba_requests_user_pending
    ON ciba_authentication_requests(user_id, created_at DESC)
    WHERE status = 'pending';
CREATE INDEX idx_ciba_requests_expiry ON ciba_authentication_requests(expires_at);
