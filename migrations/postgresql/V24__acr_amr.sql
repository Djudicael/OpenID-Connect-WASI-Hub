-- Add acr_values to auth_codes for ACR/AMR support (OIDC Core §3.1.2.1, §2.1)
ALTER TABLE authorization_codes ADD COLUMN IF NOT EXISTS acr_values JSONB DEFAULT '[]';
