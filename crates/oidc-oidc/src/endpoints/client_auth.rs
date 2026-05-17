use axum::http::HeaderMap;
use std::collections::HashMap;

use oidc_repository::repositories::client_repo::ClientRepo;

use crate::errors::OidcErrorResponse;
use crate::state::OidcState;
use crate::tokens::JwtTokenService;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresentedClientAuthMethod {
    ClientSecretBasic,
    ClientSecretPost,
    ClientAssertion,
}

pub fn detect_presented_client_auth_method(
    headers: &HeaderMap,
    params: &HashMap<String, String>,
) -> Result<PresentedClientAuthMethod, OidcErrorResponse> {
    let has_basic_auth = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|auth| auth.starts_with("Basic "));
    let has_client_assertion = params.contains_key("client_assertion");
    let has_client_secret_post = params.contains_key("client_secret");

    match (has_basic_auth, has_client_assertion, has_client_secret_post) {
        (true, false, false) => Ok(PresentedClientAuthMethod::ClientSecretBasic),
        (false, true, false) => Ok(PresentedClientAuthMethod::ClientAssertion),
        (false, false, true) => Ok(PresentedClientAuthMethod::ClientSecretPost),
        _ => Err(OidcErrorResponse::invalid_client(
            "Invalid client authentication",
        )),
    }
}

pub fn inject_basic_auth_credentials(
    headers: &HeaderMap,
    params: &mut HashMap<String, String>,
) -> Result<(), OidcErrorResponse> {
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
                                return Err(OidcErrorResponse::invalid_client(
                                    "Mismatched client_id",
                                ));
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

    Ok(())
}

pub async fn authenticate_client_for_endpoint(
    state: &OidcState,
    params: &HashMap<String, String>,
    conn: &mut oidc_repository::Connection,
    presented_auth_method: PresentedClientAuthMethod,
    endpoint_uri: &str,
) -> Result<oidc_core::models::Client, OidcErrorResponse> {
    if let Some(assertion) = params.get("client_assertion") {
        if presented_auth_method != PresentedClientAuthMethod::ClientAssertion {
            return Err(OidcErrorResponse::invalid_client(
                "Invalid client authentication",
            ));
        }
        let assertion_type = params
            .get("client_assertion_type")
            .ok_or_else(|| OidcErrorResponse::invalid_client("Missing client_assertion_type"))?;
        if assertion_type != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
            return Err(OidcErrorResponse::invalid_client(
                "Unsupported client_assertion_type",
            ));
        }

        let (_, claims, _, _) = JwtTokenService::parse_client_assertion_unverified(assertion)
            .map_err(|e| {
                OidcErrorResponse::invalid_client(format!("Invalid client assertion: {e}"))
            })?;
        if let Some(provided_client_id) = params.get("client_id") {
            if provided_client_id != &claims.iss {
                return Err(OidcErrorResponse::invalid_client("Mismatched client_id"));
            }
        }
        let client_id = claims.iss;

        let client = match ClientRepo.find_by_client_id(conn, &client_id).await {
            Ok(Some(c)) if c.enabled => c,
            Ok(Some(_)) => {
                return Err(OidcErrorResponse::invalid_client("Client is disabled"));
            }
            Ok(None) => {
                return Err(OidcErrorResponse::invalid_client("Client not found"));
            }
            Err(e) => return Err(OidcErrorResponse::from_internal(e)),
        };

        match client.token_endpoint_auth_method.as_str() {
            "private_key_jwt" => {
                let jwks = client.jwks.as_ref().ok_or_else(|| {
                    OidcErrorResponse::invalid_client("Client has no JWKS for private_key_jwt")
                })?;

                let now = chrono::Utc::now().timestamp();
                JwtTokenService::verify_client_assertion(
                    assertion,
                    jwks,
                    endpoint_uri,
                    &client_id,
                    now,
                )
                .map_err(|e| {
                    OidcErrorResponse::invalid_client(format!("JWT verification failed: {e}"))
                })?;
            }
            "client_secret_jwt" => {
                let encrypted_secret =
                    client.client_secret_encrypted.as_ref().ok_or_else(|| {
                        OidcErrorResponse::invalid_client(
                            "Client has no encrypted secret for client_secret_jwt",
                        )
                    })?;

                let client_secret = state
                    .decrypt_sensitive_string_or_plaintext(encrypted_secret)
                    .map_err(|_| {
                        OidcErrorResponse::invalid_client("Failed to decrypt client secret")
                    })?;

                let now = chrono::Utc::now().timestamp();
                crate::tokens::jwt_service::verify_client_secret_jwt(
                    assertion,
                    &client_secret,
                    endpoint_uri,
                    &client_id,
                    now,
                )
                .map_err(|e| {
                    OidcErrorResponse::invalid_client(format!("JWT verification failed: {e}"))
                })?;
            }
            _ => {
                return Err(OidcErrorResponse::invalid_client(
                    "Client not configured for JWT assertion authentication",
                ));
            }
        }

        return Ok(client);
    }

    let client_id = params
        .get("client_id")
        .ok_or_else(|| OidcErrorResponse::invalid_client("Missing client_id"))?;

    let client_secret = params
        .get("client_secret")
        .ok_or_else(|| OidcErrorResponse::invalid_client("Missing client_secret"))?;

    let client = match ClientRepo.find_by_client_id(conn, client_id).await {
        Ok(Some(c)) if c.enabled => c,
        Ok(Some(_)) => {
            return Err(OidcErrorResponse::invalid_client("Client is disabled"));
        }
        Ok(None) => {
            return Err(OidcErrorResponse::invalid_client("Client not found"));
        }
        Err(e) => return Err(OidcErrorResponse::from_internal(e)),
    };

    match client.token_endpoint_auth_method.as_str() {
        "client_secret_basic" => {
            if presented_auth_method != PresentedClientAuthMethod::ClientSecretBasic {
                return Err(OidcErrorResponse::invalid_client(
                    "Invalid client authentication",
                ));
            }
        }
        "client_secret_post" => {
            if presented_auth_method != PresentedClientAuthMethod::ClientSecretPost {
                return Err(OidcErrorResponse::invalid_client(
                    "Invalid client authentication",
                ));
            }
        }
        _ => {
            return Err(OidcErrorResponse::invalid_client(
                "Client not configured for secret authentication",
            ));
        }
    }

    if let Some(ref hash) = client.client_secret_hash {
        if !state.hasher.verify(client_secret, hash).unwrap_or(false) {
            return Err(OidcErrorResponse::invalid_client(
                "Invalid client credentials",
            ));
        }
    } else {
        return Err(OidcErrorResponse::invalid_client(
            "Public clients cannot authenticate with secret credentials",
        ));
    }

    Ok(client)
}
