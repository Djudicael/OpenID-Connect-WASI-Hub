CREATE TABLE authorization_resources (
    id UUID PRIMARY KEY,
    realm_id UUID NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    resource_server_id UUID NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    owner_id UUID REFERENCES users(id) ON DELETE SET NULL,
    name TEXT NOT NULL,
    display_name TEXT,
    resource_type TEXT,
    uris JSONB NOT NULL DEFAULT '[]'::jsonb,
    scopes JSONB NOT NULL DEFAULT '[]'::jsonb,
    attributes JSONB NOT NULL DEFAULT '{}'::jsonb,
    icon_uri TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(resource_server_id, name)
);

CREATE TABLE authorization_policies (
    id UUID PRIMARY KEY,
    realm_id UUID NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    resource_server_id UUID NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    description TEXT,
    policy_type TEXT NOT NULL CHECK (policy_type IN ('user','role','group','client','owner','attribute','time')),
    logic TEXT NOT NULL DEFAULT 'positive' CHECK (logic IN ('positive','negative')),
    config JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(resource_server_id, name)
);

CREATE TABLE authorization_permissions (
    id UUID PRIMARY KEY,
    realm_id UUID NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    resource_server_id UUID NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    description TEXT,
    resources JSONB NOT NULL DEFAULT '[]'::jsonb,
    scopes JSONB NOT NULL DEFAULT '[]'::jsonb,
    policies JSONB NOT NULL DEFAULT '[]'::jsonb,
    decision_strategy TEXT NOT NULL DEFAULT 'affirmative' CHECK (decision_strategy IN ('affirmative','unanimous','consensus')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(resource_server_id, name)
);

CREATE TABLE authorization_permission_tickets (
    id UUID PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,
    realm_id UUID NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    resource_server_id UUID NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    requester_id UUID REFERENCES users(id) ON DELETE CASCADE,
    resource_id UUID NOT NULL REFERENCES authorization_resources(id) ON DELETE CASCADE,
    scopes JSONB NOT NULL DEFAULT '[]'::jsonb,
    granted BOOLEAN NOT NULL DEFAULT FALSE,
    used BOOLEAN NOT NULL DEFAULT FALSE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE authorization_rpt_grants (
    id UUID PRIMARY KEY,
    realm_id UUID NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    resource_server_id UUID NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    subject_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id UUID NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    permissions JSONB NOT NULL,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_authorization_resources_server ON authorization_resources(resource_server_id);
CREATE INDEX idx_authorization_policies_server ON authorization_policies(resource_server_id);
CREATE INDEX idx_authorization_permissions_server ON authorization_permissions(resource_server_id);
CREATE INDEX idx_authorization_tickets_expiry ON authorization_permission_tickets(expires_at) WHERE NOT used;
CREATE INDEX idx_authorization_rpts_subject ON authorization_rpt_grants(subject_id, resource_server_id) WHERE NOT revoked;
