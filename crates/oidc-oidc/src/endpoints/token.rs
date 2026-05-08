//! Token endpoint handler.

use axum::Json;
use serde_json::Value;
use std::collections::HashMap;

use oidc_core::OidcError;

use crate::flows::authorization_code::AuthorizationCodeFlow;
use crate::flows::client_credentials::ClientCredentialsFlow;
use crate::flows::refresh_token::RefreshTokenFlow;
use crate::state::OidcState;

/// Token endpoint handler.
/// Supports `client_secret_basic` (Authorization header) and `client_secret_post` (form body).
pub async fn token_handler(
    state: OidcState,
    headers: axum::http::HeaderMap,
    mut params: HashMap<String, String>,
) -> Result<Json<Value>, OidcError> {
    // Extract client_secret_basic from Authorization header if present
    if let Some(auth_header) = headers.get(axum::http::header::AUTHORIZATION) {
        if let Ok(auth_str) = auth_header.to_str() {
            if let Some(credentials) = auth_str.strip_prefix("Basic ") {
                use base64::{Engine, engine::general_purpose::STANDARD};
                if let Ok(decoded) = STANDARD.decode(credentials) {
                    if let Ok(cred_str) = String::from_utf8(decoded) {
                        if let Some((client_id, client_secret)) = cred_str.split_once(':') {
                            params
                                .entry("client_id".to_string())
                                .or_insert_with(|| client_id.to_string());
                            params
                                .entry("client_secret".to_string())
                                .or_insert_with(|| client_secret.to_string());
                        }
                    }
                }
            }
        }
    }

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
