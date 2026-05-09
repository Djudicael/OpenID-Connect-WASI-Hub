//! API key business logic service.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{Duration, Utc};
use oidc_core::OidcError;
use oidc_core::models::ApiKey;
use oidc_repository::Connection;
use oidc_repository::repositories::api_key_repo::ApiKeyRepo;
use uuid::Uuid;

use crate::hashing;

/// Length of the random secret portion in bytes.
const SECRET_BYTES: usize = 36;
/// Prefix length extracted from the random portion.
const PREFIX_LEN: usize = 8;
/// Default grace period for rotated keys in hours.
const ROTATION_GRACE_HOURS: i64 = 24;

/// Service for managing API keys.
pub struct ApiKeyService;

impl ApiKeyService {
    /// Generate a new API key.
    ///
    /// Returns the persisted `ApiKey` model and the **raw key string** (displayed only once).
    pub async fn generate_key(
        conn: &mut Connection,
        realm_id: Uuid,
        name: String,
        scopes: Vec<String>,
        expires_in_days: Option<u32>,
        created_by: Option<Uuid>,
    ) -> Result<(ApiKey, String), OidcError> {
        let mut random_bytes = [0u8; SECRET_BYTES];
        getrandom::fill(&mut random_bytes)
            .map_err(|e| OidcError::Internal(format!("getrandom failed: {e}")))?;

        let secret = URL_SAFE_NO_PAD.encode(&random_bytes);
        let prefix = secret.chars().take(PREFIX_LEN).collect::<String>();
        let raw_key = format!("oidc_{}_{}_{}", env_segment(), prefix, secret);

        let hashed_secret = hashing::hash_secret(&raw_key)?;

        let expires_at = expires_in_days.map(|days| Utc::now() + Duration::days(days as i64));

        let api_key = ApiKey {
            id: Uuid::new_v4(),
            realm_id,
            name,
            prefix,
            hashed_secret,
            scopes,
            revoked: false,
            request_count: 0,
            expires_at,
            last_used_at: None,
            created_at: Utc::now(),
            created_by,
            rotated_at: None,
        };

        ApiKeyRepo.create(conn, &api_key).await?;

        Ok((api_key, raw_key))
    }

    /// Verify a raw API key against the database.
    ///
    /// Parses the prefix, looks up the active key by prefix, and verifies the Argon2id hash.
    /// Rejects expired, revoked, or rotated keys past grace period.
    pub async fn verify_key(conn: &mut Connection, raw_key: &str) -> Result<ApiKey, OidcError> {
        let (prefix, _env, _secret_part) = parse_key(raw_key)
            .ok_or_else(|| OidcError::AuthenticationFailed("invalid key format".into()))?;

        let api_key = ApiKeyRepo
            .find_by_prefix(conn, &prefix)
            .await?
            .ok_or_else(|| OidcError::AuthenticationFailed("unknown or revoked key".into()))?;

        // Check expiration
        if api_key.is_expired() {
            return Err(OidcError::AuthenticationFailed("key expired".into()));
        }

        // Check rotation grace period
        if let Some(rotated_at) = api_key.rotated_at {
            if Utc::now() > rotated_at + Duration::hours(ROTATION_GRACE_HOURS) {
                return Err(OidcError::AuthenticationFailed(
                    "key rotation expired".into(),
                ));
            }
        }

        if !hashing::verify_secret(raw_key, &api_key.hashed_secret)? {
            return Err(OidcError::AuthenticationFailed("invalid key".into()));
        }

        Ok(api_key)
    }

    /// Revoke an API key by ID.
    pub async fn revoke_key(conn: &mut Connection, id: Uuid) -> Result<(), OidcError> {
        ApiKeyRepo.revoke(conn, id).await
    }

    /// Rotate an API key: mark old key rotated, create new key with same metadata.
    pub async fn rotate_key(
        conn: &mut Connection,
        id: Uuid,
        expires_in_days: Option<u32>,
    ) -> Result<(ApiKey, String), OidcError> {
        let old_key = ApiKeyRepo
            .find_by_id(conn, id)
            .await?
            .ok_or_else(|| OidcError::Internal("key not found".into()))?;

        // Mark old key as rotated
        ApiKeyRepo.mark_rotated(conn, id).await?;

        // Generate new key with same metadata
        let (new_key, raw_key) = Self::generate_key(
            conn,
            old_key.realm_id,
            old_key.name,
            old_key.scopes,
            expires_in_days,
            old_key.created_by,
        )
        .await?;

        Ok((new_key, raw_key))
    }

    /// Increment the usage counter for an API key.
    pub async fn increment_usage(conn: &mut Connection, id: Uuid) -> Result<(), OidcError> {
        ApiKeyRepo.increment_count(conn, id).await
    }
}

/// Extract components from a raw key of the form `oidc_<env>_<prefix>_<secret>`.
fn parse_key(raw_key: &str) -> Option<(String, String, String)> {
    let stripped = raw_key.strip_prefix("oidc_")?;
    let mut parts = stripped.splitn(3, '_');
    let env = parts.next()?.to_string();
    let prefix = parts.next()?.to_string();
    let secret = parts.next()?.to_string();
    if prefix.len() != PREFIX_LEN {
        return None;
    }
    Some((prefix, env, secret))
}

/// Return the configurable environment segment for key prefixes.
fn env_segment() -> String {
    std::env::var("OIDC_KEY_ENV").unwrap_or_else(|_| "prod".into())
}
