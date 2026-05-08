//! Refresh Token flow.

use oidc_core::models::Session;
use oidc_core::traits::token_service::TokenService;
use oidc_core::utils::generate_uuid_v7;
use oidc_core::OidcError;
use oidc_repository::repositories::session_repo::SessionRepo;
use serde_json::{Value, json};

use crate::state::OidcState;

/// Refresh Token flow handler.
pub struct RefreshTokenFlow;

impl RefreshTokenFlow {
    /// Execute the refresh token flow.
    pub async fn execute(state: &OidcState, refresh_token: &str) -> Result<Value, OidcError> {
        let mut conn = state.connect().await?;

        let refresh_hash = sha2_256_hex(refresh_token);

        // --- Look up session by refresh token hash ---
        let session = SessionRepo
            .find_by_refresh_token_hash(&mut conn, &refresh_hash)
            .await?
            .ok_or(OidcError::InvalidRequest)?;

        if session.revoked {
            return Err(OidcError::InvalidRequest);
        }

        // --- Issue new tokens ---
        let subject = session.user_id.to_string();
        let audience = session.client_id.to_string();
        let scopes = session.scope.clone();

        let access_token = state
            .token_service
            .issue_access_token(&subject, &audience, &scopes)
            .await?;
        let id_token = state
            .token_service
            .issue_id_token(&subject, &audience, None)
            .await?;

        // --- Store new session ---
        let new_access_hash = sha2_256_hex(&access_token);
        let new_refresh_token_value = format!("{}refresh", access_token);
        let new_refresh_hash = Some(sha2_256_hex(&new_refresh_token_value));

        let new_session = Session {
            id: generate_uuid_v7(),
            user_id: session.user_id,
            realm_id: session.realm_id,
            client_id: session.client_id,
            grant_type: "refresh_token".to_string(),
            access_token_hash: new_access_hash,
            refresh_token_hash: new_refresh_hash,
            id_token_jti: None,
            scope: scopes.clone(),
            revoked: false,
        };

        SessionRepo.create(&mut conn, &new_session).await?;

        Ok(json!({
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": 900,
            "refresh_token": new_refresh_token_value,
            "id_token": id_token,
            "scope": scopes.join(" "),
        }))
    }
}

fn sha2_256_hex(data: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    let result = hasher.finalize();
    hex::encode(result)
}
