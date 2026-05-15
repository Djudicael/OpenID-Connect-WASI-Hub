-- Add claims_locales to authorization_codes for OIDC Core §3.1.2.1 / §5.2 support
ALTER TABLE authorization_codes ADD COLUMN IF NOT EXISTS claims_locales JSONB NOT NULL DEFAULT '[]';
