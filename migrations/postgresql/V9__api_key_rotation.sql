-- V9__api_key_rotation.sql
-- Add rotation tracking to API keys.

ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS rotated_at TIMESTAMPTZ;
