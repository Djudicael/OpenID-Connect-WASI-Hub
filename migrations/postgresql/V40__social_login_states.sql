CREATE TABLE IF NOT EXISTS social_login_states (
    id UUID PRIMARY KEY,
    state_token_hash TEXT NOT NULL,
    realm_id UUID NOT NULL REFERENCES realms(id),
    identity_provider_id UUID NOT NULL REFERENCES identity_providers(id),
    client_id UUID NOT NULL REFERENCES clients(id),
    redirect_uri TEXT NOT NULL,
    original_state TEXT,
    nonce TEXT,
    expires_at TIMESTAMPTZ NOT NULL,
    used BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_social_login_states_token_hash
    ON social_login_states(state_token_hash);

CREATE INDEX IF NOT EXISTS idx_social_login_states_active
    ON social_login_states(expires_at)
    WHERE used = FALSE;
