//! Client Credentials flow.

use oidc_core::OidcError;
use oidc_core::models::Session;
use oidc_core::traits::TokenService;
use oidc_core::utils::{generate_uuid_v7, sha2_256_hex};
use oidc_repository::mapper::pg_err;
use oidc_repository::repositories::client_repo::ClientRepo;
use oidc_repository::repositories::session_repo::SessionRepo;
use oidc_repository::with_transaction;
use serde_json::{Value, json};

use crate::state::OidcState;

/// Client Credentials flow handler.
pub struct ClientCredentialsFlow;

impl ClientCredentialsFlow {
    /// Execute the client credentials flow.
    ///
    /// When `dpop_jkt` is provided, the access token is bound to the DPoP
    /// key via a `cnf.jkt` claim and `token_type` is `"DPoP"` (RFC 9449).
    pub async fn execute(
        state: &OidcState,
        client_id: &str,
        client_secret: &str,
        dpop_jkt: Option<&str>,
    ) -> Result<Value, OidcError> {
        let mut conn = state.connect().await?;

        with_transaction!(conn, pg_err, {
            let client = match ClientRepo.find_by_client_id(&mut conn, client_id).await? {
                Some(c) if c.enabled => c,
                Some(_) => return Err(OidcError::InvalidClient),
                None => return Err(OidcError::InvalidClient),
            };

            match client.client_secret_hash {
                Some(ref hash) => {
                    let verified = match state.hasher.verify(client_secret, hash) {
                        Ok(v) => v,
                        Err(e) => {
                            tracing::error!("Internal error: verify failed: {}", e);
                            return Err(OidcError::Internal(e.to_string()));
                        }
                    };
                    if !verified {
                        return Err(OidcError::InvalidClient);
                    }
                }
                None => return Err(OidcError::InvalidClient),
            }

            let token_svc = state.token_service_for_realm(client.realm_id).await?;
            let access_token = token_svc
                .issue_access_token(
                    &client.client_id,
                    &client.client_id,
                    &client.allowed_scopes,
                    dpop_jkt,
                    None,
                    None,
                )
                .await?;

            let access_hash = sha2_256_hex(&access_token);
            let now = chrono::Utc::now();

            // Create a session record so the token can be introspected and revoked.
            // Client credentials have no end-user, so user_id is NULL.
            let session = Session {
                id: generate_uuid_v7(),
                sid: oidc_core::utils::generate_sid().unwrap_or_default(),
                user_id: None, // no end-user for client_credentials
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
                authorization_details: None,
                resource: vec![],
            };

            SessionRepo.create(&mut conn, &session).await?;

            let token_type = if dpop_jkt.is_some() { "DPoP" } else { "Bearer" };

            Ok(json!({
                "access_token": access_token,
                "token_type": token_type,
                "expires_in": 900,
                "scope": client.allowed_scopes.join(" "),
            }))
        })
    }
}
