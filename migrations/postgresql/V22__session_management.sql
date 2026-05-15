-- V22__session_management.sql
-- Add OIDC Session Management columns (Session §3-4, Front-Channel §6, Back-Channel §7).

-- Add sid (Session ID) column to sessions for OIDC session management.
-- This is the stable identifier used in ID tokens and logout tokens.
CREATE EXTENSION IF NOT EXISTS pgcrypto;
ALTER TABLE sessions
    ADD COLUMN IF NOT EXISTS sid TEXT;

-- Generate sid for existing sessions that don't have one.
UPDATE sessions SET sid = encode(gen_random_bytes(16), 'hex') WHERE sid IS NULL;

-- Make sid NOT NULL going forward (with a default for convenience).
ALTER TABLE sessions
    ALTER COLUMN sid SET NOT NULL,
    ALTER COLUMN sid SET DEFAULT encode(gen_random_bytes(16), 'hex');

CREATE INDEX IF NOT EXISTS idx_sessions_sid ON sessions(sid);

-- Add session management columns to clients.
ALTER TABLE clients
    ADD COLUMN IF NOT EXISTS frontchannel_logout_uri TEXT,
    ADD COLUMN IF NOT EXISTS frontchannel_logout_session_required BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS backchannel_logout_uri TEXT,
    ADD COLUMN IF NOT EXISTS backchannel_logout_session_required BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS post_logout_redirect_uris JSONB NOT NULL DEFAULT '[]';
