-- Identity providers for social login / federation
CREATE TABLE IF NOT EXISTS identity_providers (
    id UUID PRIMARY KEY,
    realm_id UUID NOT NULL REFERENCES realms(id),
    alias TEXT NOT NULL,
    display_name TEXT NOT NULL,
    provider_type TEXT NOT NULL DEFAULT 'oidc',
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    issuer TEXT NOT NULL,
    authorization_url TEXT NOT NULL,
    token_url TEXT NOT NULL,
    userinfo_url TEXT NOT NULL,
    jwks_url TEXT NOT NULL,
    client_id TEXT NOT NULL,
    client_secret TEXT NOT NULL,
    scopes JSONB DEFAULT '["openid","profile","email"]',
    auto_create_users BOOLEAN NOT NULL DEFAULT TRUE,
    link_users_by_email BOOLEAN NOT NULL DEFAULT TRUE,
    deleted_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_identity_providers_alias ON identity_providers(realm_id, alias) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_identity_providers_realm ON identity_providers(realm_id) WHERE deleted_at IS NULL;

-- Federated identities (links between local users and upstream IdPs)
CREATE TABLE IF NOT EXISTS federated_identities (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id),
    realm_id UUID NOT NULL REFERENCES realms(id),
    identity_provider_id UUID NOT NULL REFERENCES identity_providers(id),
    upstream_subject TEXT NOT NULL,
    upstream_username TEXT,
    upstream_email TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_federated_identities_subject ON federated_identities(identity_provider_id, upstream_subject);
CREATE INDEX IF NOT EXISTS idx_federated_identities_user ON federated_identities(user_id);
