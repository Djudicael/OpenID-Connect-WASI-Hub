-- V20__client_jwt_auth_columns.sql
-- Add columns to clients table for JWT-based client authentication
-- (client_secret_jwt, private_key_jwt) and PAR/Request Object support.

ALTER TABLE clients
    ADD COLUMN IF NOT EXISTS token_endpoint_auth_method TEXT NOT NULL DEFAULT 'client_secret_basic',
    ADD COLUMN IF NOT EXISTS jwks_uri TEXT,
    ADD COLUMN IF NOT EXISTS jwks JSONB,
    ADD COLUMN IF NOT EXISTS request_uris JSONB NOT NULL DEFAULT '[]',
    ADD COLUMN IF NOT EXISTS client_secret_encrypted TEXT;
