-- V17__user_standard_claims.sql
-- Add full standard OIDC user claims.

ALTER TABLE users
    ADD COLUMN middle_name TEXT,
    ADD COLUMN nickname TEXT,
    ADD COLUMN preferred_username TEXT,
    ADD COLUMN profile TEXT,
    ADD COLUMN picture TEXT,
    ADD COLUMN website TEXT,
    ADD COLUMN gender TEXT,
    ADD COLUMN birthdate TEXT,
    ADD COLUMN zoneinfo TEXT,
    ADD COLUMN phone_number_verified BOOLEAN NOT NULL DEFAULT FALSE,
    ALTER COLUMN locale SET NOT NULL,
    ALTER COLUMN locale SET DEFAULT 'en',
    ALTER COLUMN updated_at SET DEFAULT NOW();
