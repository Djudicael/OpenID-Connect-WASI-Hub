//! Client Credentials flow.

use oidc_core::OidcError;
use oidc_core::traits::TokenService;
use oidc_core::utils::sha2_256_hex;
use oidc_repository::repositories::client_repo::ClientRepo;
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
        let client = ClientRepo
            .find_by_client_id(&mut conn, client_id)
            .await?
            .ok_or(OidcError::InvalidClient)?;

        if !client.enabled {
            return Err(OidcError::InvalidClient);
        }

        match client.client_secret_hash {
            Some(ref hash) => {
                if !state.hasher.verify(client_secret, hash)? {
                    return Err(OidcError::InvalidClient);
                }
            }
            None => return Err(OidcError::InvalidClient),
        }

        let access_token = state
            .token_service
            .issue_access_token(&client.client_id, &client.client_id, &client.allowed_scopes)
            .await?;

        let _access_hash = sha2_256_hex(&access_token);

        Ok(json!({
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": 900,
            "scope": client.allowed_scopes.join(" "),
        }))
    }
}
