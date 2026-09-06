-- Keep a single actionable invitation per organization and email address.
CREATE UNIQUE INDEX uq_organization_invitations_pending_email
    ON organization_invitations (organization_id, lower(email))
    WHERE status = 'pending';
