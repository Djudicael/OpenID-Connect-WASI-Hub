CREATE TABLE account_recovery_tokens (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    realm_id UUID NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used BOOLEAN NOT NULL DEFAULT FALSE,
    used_at TIMESTAMPTZ,
    created_by UUID NOT NULL,
    creator_ip TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_account_recovery_user ON account_recovery_tokens(user_id);
CREATE INDEX idx_account_recovery_hash ON account_recovery_tokens(token_hash) WHERE used = FALSE;
CREATE INDEX idx_account_recovery_expires ON account_recovery_tokens(expires_at) WHERE used = FALSE;
