-- Add subject_type and sector_identifier_uri to clients for pairwise subject identifiers (OIDC Core §8)
ALTER TABLE clients ADD COLUMN IF NOT EXISTS subject_type TEXT NOT NULL DEFAULT 'public';
ALTER TABLE clients ADD COLUMN IF NOT EXISTS sector_identifier_uri TEXT;

-- Add pairwise_salt to realms config (stored as JSON key in config)
-- We'll use a per-realm salt stored in the realm's config JSON
