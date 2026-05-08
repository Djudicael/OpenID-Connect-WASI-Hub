//! Authorization Code + PKCE flow.

use oidc_core::OidcError;
use oidc_core::models::Session;
use oidc_core::traits::token_service::TokenService;
use oidc_core::utils::{generate_uuid_v7, verify_s256};
use oidc_repository::repositories::auth_code_repo::AuthCodeRepo;
use oidc_repository::repositories::client_repo::ClientRepo;
use oidc_repository::repositories::session_repo::SessionRepo;
use serde_json::{Value, json};

use crate::state::OidcState;

/// Authorization Code flow handler.
pub struct AuthorizationCodeFlow;

impl AuthorizationCodeFlow {
    /// Execute the authorization code flow.
    pub async fn execute(
        state: &OidcState,
        code: &str,
        redirect_uri: &str,
        client_id: &str,
        code_verifier: &str,
    ) -> Result<Value, OidcError> {
        let mut conn = state.connect().await?;

        // --- Look up and validate the authorization code ---
        let auth_code = AuthCodeRepo
            .find_by_code(&mut conn, code)
            .await?
            .ok_or(OidcError::InvalidRequest)?;

        if auth_code.used {
            return Err(OidcError::InvalidRequest);
        }

        if auth_code.redirect_uri != redirect_uri {
            return Err(OidcError::InvalidRequest);
        }

        // --- Validate client ---
        let client = ClientRepo
            .find_by_client_id(&mut conn, client_id)
            .await?
            .ok_or(OidcError::InvalidClient)?;

        if client.id != auth_code.client_id {
            return Err(OidcError::InvalidClient);
        }

        if !client.enabled {
            return Err(OidcError::InvalidClient);
        }

        // --- PKCE verification ---
        if auth_code.code_challenge_method == "S256" {
            if !verify_s256(code_verifier, &auth_code.code_challenge) {
                return Err(OidcError::InvalidRequest);
            }
        } else {
            // plain: direct comparison
            if auth_code.code_challenge != code_verifier {
                return Err(OidcError::InvalidRequest);
            }
        }

        // --- Mark code as used ---
        AuthCodeRepo.mark_used(&mut conn, auth_code.id).await?;

        // --- Issue tokens ---
        let subject = auth_code.user_id.to_string();
        let audience = client.client_id.clone();
        let scopes = auth_code.scope.clone();

        let access_token = state
            .token_service
            .issue_access_token(&subject, &audience, &scopes)
            .await?;
        let id_token = state
            .token_service
            .issue_id_token(&subject, &audience, None)
            .await?;

        // --- Store session ---
        let access_hash = sha2_256_hex(&access_token);
        let refresh_token_value = format!("{}refresh", access_token);
        let refresh_hash = Some(sha2_256_hex(&refresh_token_value));

        let session = Session {
            id: generate_uuid_v7(),
            user_id: auth_code.user_id,
            realm_id: auth_code.realm_id,
            client_id: client.id,
            grant_type: "authorization_code".to_string(),
            access_token_hash: access_hash,
            refresh_token_hash: refresh_hash,
            id_token_jti: None,
            scope: scopes.clone(),
            revoked: false,
        };

        SessionRepo.create(&mut conn, &session).await?;

        Ok(json!({
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": 900,
            "refresh_token": refresh_token_value,
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
