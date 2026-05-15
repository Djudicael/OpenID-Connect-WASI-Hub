-- V35: Add address fields to users table for OIDC Core §5.1.1 address claim support.
-- Supports European addresses: multi-line street_address (with \n),
-- generic region (French région, German Bundesland, etc.),
-- any postal code format (French 5-digit, UK alphanumeric, etc.),
-- and ISO 3166-1 country codes.
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS street_address TEXT,
    ADD COLUMN IF NOT EXISTS locality TEXT,
    ADD COLUMN IF NOT EXISTS region TEXT,
    ADD COLUMN IF NOT EXISTS postal_code TEXT,
    ADD COLUMN IF NOT EXISTS country TEXT;
