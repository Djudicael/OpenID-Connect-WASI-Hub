-- V18__auth_code_claims_request.sql
-- Add claims_request and display columns to authorization_codes for OIDC Core §5.5 claims parameter support
-- and OIDC Core §3.1.2.1 display parameter support.

ALTER TABLE authorization_codes
    ADD COLUMN claims_request JSONB,
    ADD COLUMN display TEXT;
