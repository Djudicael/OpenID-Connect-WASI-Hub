CREATE TABLE realm_signing_keys (
    realm_id UUID PRIMARY KEY REFERENCES realms(id) ON DELETE CASCADE,
    rsa_private_pem TEXT NOT NULL,
    rsa_kid VARCHAR(64) NOT NULL DEFAULT 'key-1',
    rsa_public_n TEXT NOT NULL,
    rsa_public_e TEXT NOT NULL,
    ed25519_private_pem TEXT NOT NULL,
    ed25519_kid VARCHAR(64) NOT NULL DEFAULT 'ed-key-1',
    ed25519_public_x TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_realm_signing_keys_realm_id ON realm_signing_keys(realm_id);
