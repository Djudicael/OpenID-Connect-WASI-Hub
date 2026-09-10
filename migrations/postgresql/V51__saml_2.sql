-- SAML 2.0 service providers, realm credentials, broker state and replay defence.
CREATE TABLE IF NOT EXISTS saml_realm_keys (
    realm_id UUID PRIMARY KEY REFERENCES realms(id) ON DELETE CASCADE,
    private_key_encrypted TEXT NOT NULL,
    certificate_pem TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS saml_service_providers (
    id UUID PRIMARY KEY,
    realm_id UUID NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    metadata_xml TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    require_signed_requests BOOLEAN NOT NULL DEFAULT TRUE,
    sign_responses BOOLEAN NOT NULL DEFAULT FALSE,
    sign_assertions BOOLEAN NOT NULL DEFAULT TRUE,
    encrypt_assertions BOOLEAN NOT NULL DEFAULT FALSE,
    attribute_mapping JSONB NOT NULL DEFAULT '{"email":"email","given_name":"firstName","family_name":"lastName","groups":"groups"}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ,
    UNIQUE (realm_id, entity_id),
    UNIQUE (realm_id, name)
);

ALTER TABLE identity_providers
    ADD COLUMN IF NOT EXISTS saml_metadata_xml TEXT,
    ADD COLUMN IF NOT EXISTS saml_attribute_mapping JSONB NOT NULL DEFAULT '{"email":"email","given_name":"firstName","family_name":"lastName"}';
ALTER TABLE identity_providers DROP CONSTRAINT IF EXISTS identity_providers_provider_type_check;
ALTER TABLE identity_providers ADD CONSTRAINT identity_providers_provider_type_check
    CHECK (provider_type IN ('oidc', 'google', 'github', 'saml'));

CREATE TABLE IF NOT EXISTS saml_pending_requests (
    id UUID PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,
    realm_id UUID NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    service_provider_id UUID REFERENCES saml_service_providers(id) ON DELETE CASCADE,
    identity_provider_id UUID REFERENCES identity_providers(id) ON DELETE CASCADE,
    purpose TEXT NOT NULL CHECK (purpose IN ('idp_sso', 'broker_login')),
    wire_payload TEXT,
    binding TEXT,
    relay_state TEXT,
    tracker JSONB,
    return_to TEXT,
    expires_at TIMESTAMPTZ NOT NULL,
    used BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_saml_pending_active
    ON saml_pending_requests(token_hash, expires_at) WHERE used = FALSE;

CREATE TABLE IF NOT EXISTS saml_assertion_replays (
    assertion_id TEXT PRIMARY KEY,
    realm_id UUID NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_saml_assertion_replays_expiry ON saml_assertion_replays(expires_at);
