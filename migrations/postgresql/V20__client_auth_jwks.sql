-- V20__client_auth_jwks.sql
-- Add token_endpoint_auth_method, JWKS, and request_uris support to clients.

ALTER TABLE clients
    ADD COLUMN token_endpoint_auth_method TEXT NOT NULL DEFAULT 'client_secret_basic'
        CHECK (token_endpoint_auth_method IN ('none', 'client_secret_basic', 'client_secret_post', 'client_secret_jwt', 'private_key_jwt')),
    ADD COLUMN jwks_uri TEXT,
    ADD COLUMN jwks JSONB,
    ADD COLUMN request_uris JSONB NOT NULL DEFAULT '[]';
