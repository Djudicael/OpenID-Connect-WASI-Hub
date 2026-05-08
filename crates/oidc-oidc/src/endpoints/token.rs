use axum::Json;
use serde_json::Value;
use std::collections::HashMap;

use oidc_core::OidcError;

use crate::flows::authorization_code::AuthorizationCodeFlow;
use crate::flows::client_credentials::ClientCredentialsFlow;
use crate::flows::refresh_token::RefreshTokenFlow;
use crate::state::OidcState;

/// Token endpoint handler.
pub async fn token_handler(
    state: OidcState,
    params: HashMap<String, String>,
) -> Result<Json<Value>, OidcError> {
    let grant_type = params
        .get("grant_type")
        .ok_or(OidcError::InvalidRequest)?
        .as_str();

    let result = match grant_type {
        "authorization_code" => {
            let code = params.get("code").ok_or(OidcError::InvalidRequest)?;
            let redirect_uri = params
                .get("redirect_uri")
                .ok_or(OidcError::InvalidRequest)?;
            let client_id = params.get("client_id").ok_or(OidcError::InvalidClient)?;
            let code_verifier = params
                .get("code_verifier")
                .ok_or(OidcError::InvalidRequest)?;

            AuthorizationCodeFlow::execute(&state, code, redirect_uri, client_id, code_verifier)
                .await?
        }
        "client_credentials" => {
            let client_id = params.get("client_id").ok_or(OidcError::InvalidClient)?;
            let client_secret = params
                .get("client_secret")
                .ok_or(OidcError::InvalidClient)?;

            ClientCredentialsFlow::execute(&state, client_id, client_secret).await?
        }
        "refresh_token" => {
            let refresh_token = params
                .get("refresh_token")
                .ok_or(OidcError::InvalidRequest)?;

            RefreshTokenFlow::execute(&state, refresh_token).await?
        }
        _ => return Err(OidcError::UnsupportedGrantType),
    };

    Ok(Json(result))
}
