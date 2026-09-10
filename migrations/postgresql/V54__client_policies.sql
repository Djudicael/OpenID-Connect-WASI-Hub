CREATE TABLE client_policy_profiles (
    id UUID PRIMARY KEY,
    realm_id UUID NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    description TEXT,
    executors JSONB NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(executors) = 'array'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX uq_client_policy_profile_name ON client_policy_profiles(realm_id, lower(name));

CREATE TABLE client_policies (
    id UUID PRIMARY KEY,
    realm_id UUID NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    description TEXT,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    priority INTEGER NOT NULL DEFAULT 100,
    conditions JSONB NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(conditions) = 'array'),
    profile_ids JSONB NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(profile_ids) = 'array'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX uq_client_policy_name ON client_policies(realm_id, lower(name));
CREATE INDEX idx_client_policies_evaluation ON client_policies(realm_id, enabled, priority);
