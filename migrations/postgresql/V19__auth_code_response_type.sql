-- V19__auth_code_response_type.sql
-- Add response_type column to authorization_codes for implicit/hybrid flow support.
-- Defaults to 'code' for backward compatibility with existing rows.

ALTER TABLE authorization_codes
    ADD COLUMN response_type TEXT NOT NULL DEFAULT 'code';
