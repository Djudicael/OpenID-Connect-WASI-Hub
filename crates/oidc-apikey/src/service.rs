//! API key business logic service.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use oidc_core::OidcError;
use oidc_core::models::ApiKey;
use oidc_repository::Connection;
use oidc_repository::repositories::api_key_repo::ApiKeyRepo;
use uuid::Uuid;

use crate::hashing;

/// Length of the random secret portion in bytes.
const SECRET_BYTES: usize = 32;
/// Prefix length extracted from the random portion.
const PREFIX_LEN: usize = 8;

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
    ) -> Result<(ApiKey, String), OidcError> {
        let mut random_bytes = [0u8; SECRET_BYTES];
        getrandom::fill(&mut random_bytes)
            .map_err(|e| OidcError::Internal(format!("getrandom failed: {e}")))?;

        let random_b64 = URL_SAFE_NO_PAD.encode(&random_bytes);
        let prefix = random_b64.chars().take(PREFIX_LEN).collect::<String>();
        let raw_key = format!("oidc_prod_{}", random_b64);

        let hashed_secret = hashing::hash_secret(&raw_key)?;

        let api_key = ApiKey {
            id: Uuid::new_v4(),
            realm_id,
            name,
            prefix,
            hashed_secret,
            scopes,
            revoked: false,
            request_count: 0,
        };

        ApiKeyRepo.create(conn, &api_key).await?;

        Ok((api_key, raw_key))
    }

    /// Verify a raw API key against the database.
    ///
    /// Parses the prefix, looks up the active key by prefix, and verifies the Argon2id hash.
    pub async fn verify_key(conn: &mut Connection, raw_key: &str) -> Result<ApiKey, OidcError> {
        let prefix = extract_prefix(raw_key)
            .ok_or_else(|| OidcError::AuthenticationFailed("invalid key format".into()))?;

        let api_key = ApiKeyRepo
            .find_by_prefix(conn, &prefix)
            .await?
            .ok_or_else(|| OidcError::AuthenticationFailed("unknown or revoked key".into()))?;

        if !hashing::verify_secret(raw_key, &api_key.hashed_secret)? {
            return Err(OidcError::AuthenticationFailed("invalid key".into()));
        }

        Ok(api_key)
    }

    /// Revoke an API key by ID.
    pub async fn revoke_key(conn: &mut Connection, id: Uuid) -> Result<(), OidcError> {
        ApiKeyRepo.revoke(conn, id).await
    }

    /// Increment the usage counter for an API key.
    pub async fn increment_usage(conn: &mut Connection, id: Uuid) -> Result<(), OidcError> {
        ApiKeyRepo.increment_count(conn, id).await
    }
}

/// Extract the prefix from a raw key of the form `oidc_prod_<random>`.
fn extract_prefix(raw_key: &str) -> Option<String> {
    let random_part = raw_key.strip_prefix("oidc_prod_")?;
    if random_part.len() < PREFIX_LEN {
        return None;
    }
    Some(random_part.chars().take(PREFIX_LEN).collect())
}
