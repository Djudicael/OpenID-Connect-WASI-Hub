-- V13__soft_deletes_and_fixes.sql
-- Phase 3 fixes: soft deletes for clients/realms, polymorphic audit_events.actor_id,
-- new columns for users/realms, and cleanup indexes.

-- 1. Add deleted_at to clients table
ALTER TABLE clients ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;

-- 2. Add deleted_at to realms table
ALTER TABLE realms ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;

-- 3. Drop FK constraint on audit_events.actor_id (polymorphic reference —
--    actor_id can reference users OR api_keys depending on actor_type)
ALTER TABLE audit_events DROP CONSTRAINT IF EXISTS audit_events_actor_id_fkey;

-- 4. Add phone_number to users table (if not exists from V1)
-- V1 already has phone_number, but ensure it's there
ALTER TABLE users ADD COLUMN IF NOT EXISTS phone_number TEXT;

-- 5. Add locale to users table (if not exists from V1)
-- V1 already has locale, but ensure it's there
ALTER TABLE users ADD COLUMN IF NOT EXISTS locale TEXT DEFAULT 'en';

-- 6. Add attributes to users table (if not exists from V1)
-- V1 already has attributes, but ensure it's there
ALTER TABLE users ADD COLUMN IF NOT EXISTS attributes JSONB NOT NULL DEFAULT '{}';

-- 7. Add config to realms table (if not exists from V1)
-- V1 already has config, but ensure it's there
ALTER TABLE realms ADD COLUMN IF NOT EXISTS config JSONB NOT NULL DEFAULT '{}';

-- 8. Indexes for soft-delete filtering
CREATE INDEX IF NOT EXISTS idx_clients_deleted_at ON clients(deleted_at) WHERE deleted_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_realms_deleted_at ON realms(deleted_at) WHERE deleted_at IS NOT NULL;

-- 9. Indexes for cleanup_expired queries
-- NOTE: NOW() / CURRENT_TIMESTAMP are STABLE, not IMMUTABLE, so they cannot
-- be used in partial index predicates. Use a plain btree index on expires_at
-- instead; the cleanup query will filter with WHERE expires_at < NOW() at
-- runtime, and the index will still be used for the scan.
CREATE INDEX IF NOT EXISTS idx_sessions_cleanup ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_auth_codes_cleanup ON authorization_codes(expires_at);
