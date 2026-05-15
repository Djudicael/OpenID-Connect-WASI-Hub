-- Roles table
CREATE TABLE roles (
    id UUID PRIMARY KEY,
    realm_id UUID NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    description TEXT,
    permissions JSONB NOT NULL DEFAULT '[]',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);

-- Groups table
CREATE TABLE groups (
    id UUID PRIMARY KEY,
    realm_id UUID NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    description TEXT,
    parent_id UUID REFERENCES groups(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);

-- User-Role junction table
CREATE TABLE user_roles (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, role_id)
);

-- User-Group junction table
CREATE TABLE user_groups (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, group_id)
);

-- Group-Role junction table
CREATE TABLE group_roles (
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (group_id, role_id)
);

-- Partial unique indexes
CREATE UNIQUE INDEX uq_roles_realm_name
ON roles(realm_id, name)
WHERE deleted_at IS NULL;

CREATE UNIQUE INDEX uq_groups_realm_name
ON groups(realm_id, name)
WHERE deleted_at IS NULL;

-- Indexes
CREATE INDEX idx_roles_realm
ON roles(realm_id)
WHERE deleted_at IS NULL;

CREATE INDEX idx_groups_realm
ON groups(realm_id)
WHERE deleted_at IS NULL;

CREATE INDEX idx_user_roles_user
ON user_roles(user_id);

CREATE INDEX idx_user_roles_role
ON user_roles(role_id);

CREATE INDEX idx_user_groups_user
ON user_groups(user_id);

CREATE INDEX idx_user_groups_group
ON user_groups(group_id);

CREATE INDEX idx_group_roles_group
ON group_roles(group_id);

CREATE INDEX idx_group_roles_role
ON group_roles(role_id);

CREATE INDEX idx_groups_parent
ON groups(parent_id)
WHERE parent_id IS NOT NULL;
