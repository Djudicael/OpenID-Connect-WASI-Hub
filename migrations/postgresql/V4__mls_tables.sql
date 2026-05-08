-- V4__mls_tables.sql
-- Messaging Layer Security group and KeyPackage storage.

CREATE TABLE IF NOT EXISTS mls_groups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    group_id BYTEA NOT NULL UNIQUE,
    realm_id UUID NOT NULL REFERENCES realms(id),
    epoch BIGINT NOT NULL DEFAULT 0,
    roster_hash BYTEA,
    group_state_encrypted BYTEA NOT NULL,
    welcome_message BYTEA,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS mls_members (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    group_id UUID NOT NULL REFERENCES mls_groups(id),
    user_id UUID NOT NULL REFERENCES users(id),
    credential BYTEA NOT NULL,
    leaf_index INTEGER NOT NULL,
    added_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    removed_at TIMESTAMPTZ,
    UNIQUE(group_id, user_id)
);

CREATE TABLE IF NOT EXISTS mls_key_packages (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id),
    key_package_ref BYTEA NOT NULL UNIQUE,
    key_package_encrypted BYTEA NOT NULL,
    used BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS mls_commits (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    group_id UUID NOT NULL REFERENCES mls_groups(id),
    epoch BIGINT NOT NULL,
    commit_data BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
