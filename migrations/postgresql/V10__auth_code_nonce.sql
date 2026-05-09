-- V10__auth_code_nonce.sql
-- Add OIDC nonce column to authorization codes table.

ALTER TABLE authorization_codes ADD COLUMN IF NOT EXISTS nonce TEXT;
