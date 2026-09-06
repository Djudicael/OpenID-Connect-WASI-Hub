-- Organization behavior required by interactive login and safe domain ownership.
ALTER TABLE organizations ADD COLUMN redirect_url TEXT;
CREATE UNIQUE INDEX uq_organizations_realm_name
    ON organizations(realm_id, lower(name)) WHERE deleted_at IS NULL;

ALTER TABLE organization_domains ADD COLUMN verification_token_hash TEXT;

CREATE TABLE organization_groups (
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    PRIMARY KEY (organization_id, group_id)
);
CREATE INDEX idx_organization_groups_group ON organization_groups(group_id);
