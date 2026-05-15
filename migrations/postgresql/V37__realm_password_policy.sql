-- Password policies are stored in realms.config JSONB under the "password_policy" key.
-- Example: {"password_policy": {"min_length": 12, "require_special": true}}
-- No schema changes needed — the config column already exists.
-- This migration exists for documentation and to set a default policy on existing realms.

-- Set default password policy on existing realms that don't have one
UPDATE realms
SET config = COALESCE(config, '{}'::jsonb) || '{"password_policy": {"min_length": 8, "require_uppercase": true, "require_lowercase": true, "require_digit": true}}'::jsonb
WHERE (config->'password_policy') IS NULL AND deleted_at IS NULL;
