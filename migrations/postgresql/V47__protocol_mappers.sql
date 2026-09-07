ALTER TABLE client_scopes
    ADD COLUMN assignment_type TEXT NOT NULL DEFAULT 'optional'
        CHECK (assignment_type IN ('default', 'optional'));

CREATE TABLE protocol_mappers (
    id UUID PRIMARY KEY,
    scope_id UUID NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    mapper_type TEXT NOT NULL CHECK (mapper_type IN (
        'user_property', 'user_attribute', 'hardcoded_claim',
        'audience', 'realm_roles', 'client_roles'
    )),
    claim_name TEXT,
    source TEXT,
    claim_value JSONB,
    multivalued BOOLEAN NOT NULL DEFAULT FALSE,
    add_to_access_token BOOLEAN NOT NULL DEFAULT TRUE,
    add_to_id_token BOOLEAN NOT NULL DEFAULT TRUE,
    add_to_userinfo BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(scope_id, name)
);

CREATE INDEX idx_protocol_mappers_scope ON protocol_mappers(scope_id);
