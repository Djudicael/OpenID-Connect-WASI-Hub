//! Token endpoint handler.

use axum::Json;
use serde_json::Value;
use std::collections::HashMap;

use oidc_core::OidcError;
use oidc_core::models::ClientType;

use oidc_repository::repositories::client_repo::ClientRepo;

use crate::flows::authorization_code::AuthorizationCodeFlow;
use crate::flows::client_credentials::ClientCredentialsFlow;
use crate::flows::device_code::DeviceCodeFlow;
use crate::flows::jwt_bearer::JwtBearerFlow;
use crate::flows::refresh_token::RefreshTokenFlow;
use crate::flows::token_exchange::TokenExchangeFlow;
use crate::state::OidcState;
use crate::tokens::JwtTokenService;
use crate::tokens::dpop::verify_dpop_proof;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PresentedClientAuthMethod {
    None,
    ClientSecretBasic,
    ClientSecretPost,
    ClientAssertion,
}

/// Token endpoint handler.
/// Supports `client_secret_basic` (Authorization header), `client_secret_post`
/// (form body), `private_key_jwt` (client_assertion JWT), and `client_secret_jwt`
/// (client_assertion JWT signed with HMAC) per RFC 7523.
///
/// Also supports DPoP (RFC 9449): when a `DPoP` header is present, the proof
/// is verified and the access token is bound to the client's key via a `cnf.jkt`
/// claim. The response `token_type` is `"DPoP"` instead of `"Bearer"`.
pub async fn token_handler(
    state: OidcState,
    headers: axum::http::HeaderMap,
    params: HashMap<String, String>,
) -> Result<Json<Value>, OidcError> {
    let token_endpoint_uri = state.token_endpoint_uri();
    token_handler_with_endpoint_uri(state, headers, params, &token_endpoint_uri).await
}

pub async fn token_handler_with_endpoint_uri(
    state: OidcState,
    headers: axum::http::HeaderMap,
    mut params: HashMap<String, String>,
    token_endpoint_uri: &str,
) -> Result<Json<Value>, OidcError> {
    let has_basic_auth = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|auth| auth.starts_with("Basic "));
    let has_client_assertion = params.contains_key("client_assertion");
    let has_client_secret_post = params.contains_key("client_secret");

    let presented_auth_method = match (has_basic_auth, has_client_assertion, has_client_secret_post)
    {
        (true, false, false) => PresentedClientAuthMethod::ClientSecretBasic,
        (false, true, false) => PresentedClientAuthMethod::ClientAssertion,
        (false, false, true) => PresentedClientAuthMethod::ClientSecretPost,
        (false, false, false) => PresentedClientAuthMethod::None,
        _ => return Err(OidcError::InvalidClient),
    };

    // Extract client_secret_basic from Authorization header if present
    if let Some(auth_header) = headers.get(axum::http::header::AUTHORIZATION) {
        if let Ok(auth_str) = auth_header.to_str() {
            if let Some(credentials) = auth_str.strip_prefix("Basic ") {
                use base64::{Engine, engine::general_purpose::STANDARD};
                if let Ok(decoded) = STANDARD.decode(credentials) {
                    if let Ok(cred_str) = String::from_utf8(decoded) {
                        if let Some((client_id, client_secret)) = cred_str.split_once(':') {
                            if params
                                .get("client_id")
                                .is_some_and(|provided| provided != client_id)
                            {
                                return Err(OidcError::InvalidClient);
                            }
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

    // ── Client authentication ──────────────────────────────────────────
    let (client, client_id) =
        authenticate_client(&state, &params, presented_auth_method, token_endpoint_uri).await?;

    // Check grant type is allowed
    if !client.allowed_grant_types.contains(&grant_type.to_string()) {
        return Err(OidcError::UnauthorizedClient);
    }

    // ── DPoP proof verification (RFC 9449) ──────────────────────────────
    let dpop_jkt: Option<String> = if let Some(dpop_header) = headers.get("DPoP") {
        let dpop_value = dpop_header
            .to_str()
            .map_err(|_| OidcError::InvalidDPoPProof("DPoP header is not valid UTF-8".into()))?;

        let now = chrono::Utc::now().timestamp();

        // At the token endpoint, no access_token exists yet, so ath is NOT required
        let proof = verify_dpop_proof(dpop_value, "POST", token_endpoint_uri, None, now)?;

        Some(proof.jwk_thumbprint)
    } else {
        None
    };

    let result = match grant_type {
        "authorization_code" => {
            let code = params.get("code").ok_or(OidcError::InvalidRequest)?;
            let redirect_uri = params
                .get("redirect_uri")
                .ok_or(OidcError::InvalidRequest)?;
            let code_verifier = params
                .get("code_verifier")
                .ok_or(OidcError::InvalidRequest)?;

            AuthorizationCodeFlow::execute(
                &state,
                code,
                redirect_uri,
                &client_id,
                code_verifier,
                dpop_jkt.as_deref(),
            )
            .await?
        }
        "client_credentials" => {
            ClientCredentialsFlow::execute(&state, &client, dpop_jkt.as_deref()).await?
        }
        "refresh_token" => {
            let refresh_token = params
                .get("refresh_token")
                .ok_or(OidcError::InvalidRequest)?;

            RefreshTokenFlow::execute(&state, refresh_token, client.id, dpop_jkt.as_deref()).await?
        }
        "urn:ietf:params:oauth:grant-type:device_code" => {
            let device_code = params.get("device_code").ok_or(OidcError::InvalidRequest)?;

            DeviceCodeFlow::execute(&state, device_code, &client_id, dpop_jkt.as_deref()).await?
        }
        "urn:ietf:params:oauth:grant-type:jwt-bearer" => {
            let assertion = params.get("assertion").ok_or(OidcError::InvalidRequest)?;
            let scope = params.get("scope").map(|s| s.as_str());

            JwtBearerFlow::execute(&state, assertion, scope, &client_id, dpop_jkt.as_deref())
                .await?
        }
        "urn:ietf:params:oauth:grant-type:token-exchange" => {
            let subject_token = params
                .get("subject_token")
                .ok_or(OidcError::InvalidRequest)?;
            let subject_token_type = params
                .get("subject_token_type")
                .ok_or(OidcError::InvalidRequest)?;
            let actor_token = params.get("actor_token").map(|s| s.as_str());
            let actor_token_type = params.get("actor_token_type").map(|s| s.as_str());
            let resource = params.get("resource").map(|s| s.as_str());
            let audience = params.get("audience").map(|s| s.as_str());
            let scope_str = params.get("scope").map(|s| s.as_str());
            let requested_token_type = params.get("requested_token_type").map(|s| s.as_str());

            // Parse space-separated scope string into Vec<String>
            let scopes: Option<Vec<String>> =
                scope_str.map(|s| s.split_whitespace().map(String::from).collect());

            TokenExchangeFlow::execute(
                &state,
                subject_token,
                subject_token_type,
                actor_token,
                actor_token_type,
                resource,
                audience,
                scopes.as_deref(),
                requested_token_type,
                &client_id,
                dpop_jkt.as_deref(),
            )
            .await?
        }
        _ => return Err(OidcError::UnsupportedGrantType),
    };

    Ok(Json(result))
}

/// Authenticate the client using one of the supported methods.
///
/// Priority:
/// 1. `private_key_jwt` / `client_secret_jwt` via `client_assertion` + `client_assertion_type`
/// 2. `client_secret_basic` / `client_secret_post` via `client_id` + `client_secret`
///
/// Returns the authenticated `Client` and its `client_id` string.
async fn authenticate_client(
    state: &OidcState,
    params: &HashMap<String, String>,
    presented_auth_method: PresentedClientAuthMethod,
    token_endpoint_uri: &str,
) -> Result<(oidc_core::models::Client, String), OidcError> {
    if let Some(assertion) = params.get("client_assertion") {
        if presented_auth_method != PresentedClientAuthMethod::ClientAssertion {
            return Err(OidcError::InvalidClient);
        }
        let assertion_type = params
            .get("client_assertion_type")
            .ok_or(OidcError::InvalidClient)?;
        if assertion_type != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
            return Err(OidcError::InvalidClient);
        }

        let (_, claims, _, _) = JwtTokenService::parse_client_assertion_unverified(assertion)?;
        if let Some(provided_client_id) = params.get("client_id") {
            if provided_client_id != &claims.iss {
                return Err(OidcError::InvalidClient);
            }
        }
        let client_id = claims.iss;

        let mut conn = state.connect().await?;
        let client = ClientRepo
            .find_by_client_id(&mut conn, &client_id)
            .await?
            .ok_or(OidcError::InvalidClient)?;

        if !client.enabled {
            return Err(OidcError::InvalidClient);
        }

        match client.token_endpoint_auth_method.as_str() {
            "private_key_jwt" => {
                let jwks = client.jwks.as_ref().ok_or_else(|| {
                    OidcError::InvalidClientAssertion("client has no jwks".into())
                })?;

                let now = chrono::Utc::now().timestamp();
                JwtTokenService::verify_client_assertion(
                    assertion,
                    jwks,
                    token_endpoint_uri,
                    &client_id,
                    now,
                )?;
            }
            "client_secret_jwt" => {
                let encrypted_secret =
                    client.client_secret_encrypted.as_ref().ok_or_else(|| {
                        OidcError::InvalidClientAssertion(
                            "client has no encrypted secret for client_secret_jwt".into(),
                        )
                    })?;

                let client_secret_bytes = state
                    .decrypt_client_encryption_key(encrypted_secret)
                    .map_err(|_| {
                        OidcError::InvalidClientAssertion("failed to decrypt client secret".into())
                    })?;
                let client_secret = String::from_utf8(client_secret_bytes).map_err(|_| {
                    OidcError::InvalidClientAssertion("invalid client secret encoding".into())
                })?;

                let now = chrono::Utc::now().timestamp();
                crate::tokens::jwt_service::verify_client_secret_jwt(
                    assertion,
                    &client_secret,
                    token_endpoint_uri,
                    &client_id,
                    now,
                )?;
            }
            _ => {
                return Err(OidcError::InvalidClient);
            }
        }

        return Ok((client, client_id));
    }

    // --- client_secret_basic / client_secret_post ---
    let client_id = params
        .get("client_id")
        .ok_or(OidcError::InvalidClient)?
        .clone();

    let mut conn = state.connect().await?;
    let client = ClientRepo
        .find_by_client_id(&mut conn, &client_id)
        .await?
        .ok_or(OidcError::InvalidClient)?;

    if !client.enabled {
        return Err(OidcError::InvalidClient);
    }

    match client.token_endpoint_auth_method.as_str() {
        "none" => {
            if presented_auth_method != PresentedClientAuthMethod::None
                || matches!(client.client_type, ClientType::Confidential)
            {
                return Err(OidcError::InvalidClient);
            }
        }
        "client_secret_basic" => {
            if presented_auth_method != PresentedClientAuthMethod::ClientSecretBasic {
                return Err(OidcError::InvalidClient);
            }
            let client_secret = params
                .get("client_secret")
                .ok_or(OidcError::InvalidClient)?;
            let hash = client
                .client_secret_hash
                .as_ref()
                .ok_or(OidcError::InvalidClient)?;
            if !state.hasher.verify(client_secret, hash)? {
                return Err(OidcError::InvalidClient);
            }
        }
        "client_secret_post" => {
            if presented_auth_method != PresentedClientAuthMethod::ClientSecretPost {
                return Err(OidcError::InvalidClient);
            }
            let client_secret = params
                .get("client_secret")
                .ok_or(OidcError::InvalidClient)?;
            let hash = client
                .client_secret_hash
                .as_ref()
                .ok_or(OidcError::InvalidClient)?;
            if !state.hasher.verify(client_secret, hash)? {
                return Err(OidcError::InvalidClient);
            }
        }
        "private_key_jwt" | "client_secret_jwt" => {
            // These methods must authenticate through the client_assertion path above.
            return Err(OidcError::InvalidClient);
        }
        _ => return Err(OidcError::InvalidClient),
    }

    Ok((client, client_id))
}
