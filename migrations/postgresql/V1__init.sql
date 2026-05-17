-- V1__init.sql
-- Finalized baseline schema for realms and users.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS realms (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    config JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_realms_deleted_at
    ON realms(deleted_at)
    WHERE deleted_at IS NOT NULL;

CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    realm_id UUID NOT NULL REFERENCES realms(id),
    email TEXT NOT NULL,
    email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    username TEXT,
    password_hash TEXT,
    given_name TEXT,
    family_name TEXT,
    middle_name TEXT,
    nickname TEXT,
    preferred_username TEXT,
    profile TEXT,
    picture TEXT,
    website TEXT,
    gender TEXT,
    birthdate TEXT,
    zoneinfo TEXT,
    phone_number TEXT,
    phone_number_verified BOOLEAN NOT NULL DEFAULT FALSE,
    street_address TEXT,
    locality TEXT,
    region TEXT,
    postal_code TEXT,
    country TEXT,
    locale TEXT NOT NULL DEFAULT 'en',
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    attributes JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ,
    UNIQUE(realm_id, email)
);

CREATE INDEX IF NOT EXISTS idx_users_realm_email
    ON users(realm_id, email)
    WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_users_created_at
    ON users(created_at);
