-- First-class business tenants within a realm.

CREATE TABLE organizations (
    id UUID PRIMARY KEY,
    realm_id UUID NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    alias TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    attributes JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ,
    CONSTRAINT organizations_attributes_object CHECK (jsonb_typeof(attributes) = 'object')
);

CREATE UNIQUE INDEX uq_organizations_realm_alias
    ON organizations(realm_id, alias) WHERE deleted_at IS NULL;
CREATE INDEX idx_organizations_realm
    ON organizations(realm_id) WHERE deleted_at IS NULL;

CREATE TABLE organization_domains (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    domain TEXT NOT NULL,
    kind TEXT NOT NULL DEFAULT 'exact' CHECK (kind IN ('exact', 'wildcard')),
    verified BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(organization_id, domain, kind)
);

CREATE INDEX idx_organization_domains_lookup ON organization_domains(lower(domain));

CREATE TABLE organization_memberships (
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    membership_kind TEXT NOT NULL DEFAULT 'unmanaged'
        CHECK (membership_kind IN ('managed', 'unmanaged')),
    joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (organization_id, user_id)
);

CREATE INDEX idx_organization_memberships_user ON organization_memberships(user_id);

CREATE TABLE organization_identity_providers (
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    identity_provider_id UUID NOT NULL REFERENCES identity_providers(id) ON DELETE CASCADE,
    redirect_on_email_domain BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY (organization_id, identity_provider_id)
);

CREATE TABLE organization_invitations (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    first_name TEXT,
    last_name TEXT,
    token_hash TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'accepted', 'revoked', 'expired')),
    invited_by UUID REFERENCES users(id) ON DELETE SET NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    accepted_at TIMESTAMPTZ
);

CREATE INDEX idx_organization_invitations_org_status
    ON organization_invitations(organization_id, status);
