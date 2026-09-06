-- TOTP, WebAuthn/passkeys, one-time recovery codes, and short-lived ceremonies.
CREATE TABLE user_totp_credentials (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    secret_encrypted TEXT NOT NULL,
    label TEXT NOT NULL DEFAULT 'Authenticator app',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ
);

CREATE TABLE user_webauthn_credentials (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id TEXT NOT NULL UNIQUE,
    credential JSONB NOT NULL,
    label TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ
);
CREATE INDEX idx_user_webauthn_credentials_user ON user_webauthn_credentials(user_id);

CREATE TABLE user_recovery_codes (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    used_at TIMESTAMPTZ
);
CREATE INDEX idx_user_recovery_codes_available ON user_recovery_codes(user_id) WHERE used_at IS NULL;

CREATE TABLE mfa_ceremonies (
    id UUID PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    realm_id UUID NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    client_id UUID REFERENCES clients(id) ON DELETE CASCADE,
    purpose TEXT NOT NULL CHECK (purpose IN ('login', 'totp_enrollment', 'webauthn_enrollment')),
    state JSONB NOT NULL DEFAULT '{}'::jsonb,
    attempts INTEGER NOT NULL DEFAULT 0,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_mfa_ceremonies_user ON mfa_ceremonies(user_id);
CREATE INDEX idx_mfa_ceremonies_expiry ON mfa_ceremonies(expires_at);

ALTER TABLE sessions ADD COLUMN acr TEXT NOT NULL DEFAULT 'urn:mace:incommon:iap:bronze';
ALTER TABLE sessions ADD COLUMN amr JSONB NOT NULL DEFAULT '["pwd"]'::jsonb;
ALTER TABLE authorization_codes ADD COLUMN auth_acr TEXT NOT NULL DEFAULT 'urn:mace:incommon:iap:bronze';
ALTER TABLE authorization_codes ADD COLUMN auth_amr JSONB NOT NULL DEFAULT '["pwd"]'::jsonb;
