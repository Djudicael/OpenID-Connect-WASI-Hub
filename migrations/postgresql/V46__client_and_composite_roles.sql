ALTER TABLE roles
    ADD COLUMN client_id UUID REFERENCES clients(id) ON DELETE CASCADE;

DROP INDEX IF EXISTS uq_roles_realm_name;

CREATE UNIQUE INDEX uq_realm_roles_name
ON roles(realm_id, name)
WHERE deleted_at IS NULL AND client_id IS NULL;

CREATE UNIQUE INDEX uq_client_roles_name
ON roles(client_id, name)
WHERE deleted_at IS NULL AND client_id IS NOT NULL;

CREATE INDEX idx_roles_client
ON roles(client_id)
WHERE deleted_at IS NULL AND client_id IS NOT NULL;

CREATE TABLE role_composites (
    parent_role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    child_role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (parent_role_id, child_role_id),
    CHECK (parent_role_id <> child_role_id)
);

CREATE INDEX idx_role_composites_child
ON role_composites(child_role_id);
