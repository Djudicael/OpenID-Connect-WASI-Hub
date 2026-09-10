-- Restrict which organization attributes are copied into OIDC claims.
ALTER TABLE organizations
    ADD COLUMN claim_attribute_names JSONB NOT NULL DEFAULT '[]';

ALTER TABLE organizations
    ADD CONSTRAINT organizations_claim_attribute_names_array
    CHECK (jsonb_typeof(claim_attribute_names) = 'array');

CREATE UNIQUE INDEX uq_organization_managed_user
    ON organization_memberships(user_id) WHERE membership_kind = 'managed';

-- A domain may belong to only one organization in a realm. The advisory lock
-- also serializes concurrent attempts to claim the same normalized domain.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM organization_domains domain
        JOIN organizations organization ON organization.id = domain.organization_id
        WHERE organization.deleted_at IS NULL
        GROUP BY organization.realm_id, lower(domain.domain)
        HAVING COUNT(DISTINCT domain.organization_id) > 1
    ) THEN
        RAISE EXCEPTION 'duplicate organization domains exist within a realm';
    END IF;
END;
$$;

CREATE FUNCTION enforce_organization_domain_realm_unique() RETURNS trigger AS $$
DECLARE
    target_realm UUID;
BEGIN
    SELECT realm_id INTO target_realm FROM organizations WHERE id = NEW.organization_id;
    PERFORM pg_advisory_xact_lock(hashtext(lower(NEW.domain)));
    IF EXISTS (
        SELECT 1 FROM organization_domains existing
        JOIN organizations organization ON organization.id = existing.organization_id
        WHERE organization.realm_id = target_realm
          AND organization.deleted_at IS NULL
          AND existing.organization_id <> NEW.organization_id
          AND lower(existing.domain) = lower(NEW.domain)
    ) THEN
        RAISE EXCEPTION 'organization domain already belongs to another organization'
            USING ERRCODE = '23505';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER organization_domain_realm_unique
    BEFORE INSERT OR UPDATE OF domain, organization_id ON organization_domains
    FOR EACH ROW EXECUTE FUNCTION enforce_organization_domain_realm_unique();
