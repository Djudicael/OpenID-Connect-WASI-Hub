CREATE TABLE IF NOT EXISTS user_federation_providers (
    id UUID PRIMARY KEY,
    realm_id UUID NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    provider_type TEXT NOT NULL CHECK (provider_type IN ('ldap', 'active_directory', 'kerberos')),
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    priority INTEGER NOT NULL DEFAULT 0,
    gateway_url TEXT NOT NULL,
    gateway_secret TEXT NOT NULL,
    config JSONB NOT NULL DEFAULT '{}',
    import_users BOOLEAN NOT NULL DEFAULT TRUE,
    sync_groups BOOLEAN NOT NULL DEFAULT TRUE,
    last_sync_at TIMESTAMPTZ,
    last_sync_status TEXT CHECK (last_sync_status IN ('success', 'failed')),
    last_sync_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ,
    UNIQUE (realm_id, name)
);

CREATE INDEX IF NOT EXISTS idx_user_federation_enabled
    ON user_federation_providers(realm_id, priority, name)
    WHERE enabled = TRUE AND deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS federated_directory_users (
    id UUID PRIMARY KEY,
    provider_id UUID NOT NULL REFERENCES user_federation_providers(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    external_id TEXT NOT NULL,
    external_username TEXT NOT NULL,
    external_dn TEXT,
    last_login_at TIMESTAMPTZ,
    last_synced_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (provider_id, external_id),
    UNIQUE (provider_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_federated_directory_users_user
    ON federated_directory_users(user_id);
