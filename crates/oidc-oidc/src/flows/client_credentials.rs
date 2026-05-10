//! Client Credentials flow.

use oidc_core::OidcError;
use oidc_core::models::Session;
use oidc_core::traits::TokenService;
use oidc_core::utils::{generate_uuid_v7, sha2_256_hex};
use oidc_repository::mapper::pg_err;
use oidc_repository::repositories::client_repo::ClientRepo;
use oidc_repository::repositories::session_repo::SessionRepo;
use serde_json::{Value, json};

use crate::state::OidcState;

/// Client Credentials flow handler.
pub struct ClientCredentialsFlow;

impl ClientCredentialsFlow {
    /// Execute the client credentials flow.
    pub async fn execute(
        state: &OidcState,
        client_id: &str,
        client_secret: &str,
    ) -> Result<Value, OidcError> {
        let mut conn = state.connect().await?;
        conn.begin().await.map_err(pg_err)?;

        let client = match ClientRepo.find_by_client_id(&mut conn, client_id).await? {
            Some(c) if c.enabled => c,
            Some(_) => {
                let _ = conn.rollback().await;
                return Err(OidcError::InvalidClient);
            }
            None => {
                let _ = conn.rollback().await;
                return Err(OidcError::InvalidClient);
            }
        };

        match client.client_secret_hash {
            Some(ref hash) => {
                let verified = match state.hasher.verify(client_secret, hash) {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::error!("Internal error: verify failed: {}", e);
                        let _ = conn.rollback().await;
                        return Err(OidcError::Internal(e.to_string()));
                    }
                };
                if !verified {
                    let _ = conn.rollback().await;
                    return Err(OidcError::InvalidClient);
                }
            }
            None => {
                let _ = conn.rollback().await;
                return Err(OidcError::InvalidClient);
            }
        }

        let access_token = state
            .token_service
            .issue_access_token(&client.client_id, &client.client_id, &client.allowed_scopes)
            .await?;

        let access_hash = sha2_256_hex(&access_token);
        let now = chrono::Utc::now();

        // Create a session record so the token can be introspected and revoked
        let session = Session {
            id: generate_uuid_v7(),
            user_id: client.id, // For client credentials, use client's internal ID
            realm_id: client.realm_id,
            client_id: client.id,
            grant_type: "client_credentials".to_string(),
            access_token_hash: access_hash,
            refresh_token_hash: None, // No refresh token for client credentials
            id_token_jti: None,
            scope: client.allowed_scopes.clone(),
            revoked: false,
            expires_at: now + chrono::Duration::minutes(15),
            refresh_expires_at: None,
            created_at: now,
            last_used_at: None,
            token_family_id: None,
            previous_session_id: None,
            rotated_at: None,
            reused_at: None,
            family_revoked: false,
        };

        if let Err(e) = SessionRepo.create(&mut conn, &session).await {
            let _ = conn.rollback().await;
            return Err(e);
        }
        if let Err(e) = conn.commit().await {
            let _ = conn.rollback().await;
            return Err(pg_err(e));
        }

        Ok(json!({
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": 900,
            "scope": client.allowed_scopes.join(" "),
        }))
    }
}
