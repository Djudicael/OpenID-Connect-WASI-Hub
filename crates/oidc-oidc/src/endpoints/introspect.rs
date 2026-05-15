use axum::Json;
use axum::extract::State;
use serde_json::{Value, json};
use std::collections::HashMap;

use oidc_core::traits::TokenService;
use oidc_repository::repositories::client_repo::ClientRepo;
use oidc_repository::repositories::session_repo::SessionRepo;
use oidc_repository::repositories::user_repo::UserRepo;
use oidc_repository::with_transaction;

use crate::errors::OidcErrorResponse;
use crate::state::OidcState;
use crate::tokens::JwtTokenService;

/// Token introspection endpoint handler.
/// Requires client authentication (`client_secret_basic`, `client_secret_post`,
/// `private_key_jwt`, or `client_secret_jwt` per RFC 7523).
/// Per RFC 7662, returns `active`, `sub`, `client_id`, `scope`, `token_type`,
/// `exp`, and `iat` from the verified JWT claims.
///
/// When the access token is DPoP-bound (has a `cnf` claim), the `cnf` claim
/// is included in the introspection response per RFC 9449.
pub async fn introspect_handler(
    State(state): State<OidcState>,
    axum::extract::Form(mut params): axum::extract::Form<HashMap<String, String>>,
) -> Result<Json<Value>, OidcErrorResponse> {
    // --- Extract client_secret_basic from Authorization header if present ---
    if let Some(auth_header) = params.get("Authorization") {
        if let Some(credentials) = auth_header.strip_prefix("Basic ") {
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

    let token = params
        .get("token")
        .ok_or_else(|| OidcErrorResponse::invalid_request("Missing token"))?;

    let mut conn = state
        .connect()
        .await
        .map_err(|e| OidcErrorResponse::from_internal(e))?;

    let result = with_transaction!(conn, |e| OidcErrorResponse::from_internal(e), {
        // --- Client authentication ---
        let _client = authenticate_client_introspect(&state, &params, &mut conn).await?;

        // Verify the token signature, expiry, and extract full claims
        let claims = match state
            .token_service
            .verify_access_token_with_claims(token)
            .await
        {
            Ok(c) => c,
            Err(_) => return Ok(Json(json!({"active": false}))),
        };

        // Look up the session by access token hash to confirm it is not revoked
        let access_hash = oidc_core::utils::sha2_256_hex(token);
        let _session = match SessionRepo
            .find_by_access_token_hash(&mut conn, &access_hash)
            .await
        {
            Ok(Some(s)) if !s.revoked => s,
            Ok(Some(_)) => return Ok(Json(json!({"active": false}))),
            Ok(None) => return Ok(Json(json!({"active": false}))),
            Err(e) => return Err(OidcErrorResponse::from_internal(e)),
        };

        // Look up the user by sub to get the email for the `username` field
        let username = match uuid::Uuid::parse_str(&claims.sub) {
            Ok(user_id) => UserRepo
                .find_by_id(&mut conn, user_id)
                .await
                .ok()
                .flatten()
                .and_then(|u| u.username.clone().or(Some(u.email.clone()))),
            Err(_) => None,
        };

        // Determine token_type: DPoP if cnf.jkt is present, Bearer otherwise
        let token_type = if claims.cnf.is_some() {
            "DPoP"
        } else {
            "Bearer"
        };

        // Extract audience — may be a string or array (RFC 8707)
        let aud_value = &claims.aud;
        let client_id_from_aud = match aud_value {
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Array(arr) => arr
                .first()
                .and_then(|v| v.as_str())
                .unwrap_or(&claims.aud.to_string())
                .to_string(),
            _ => claims.aud.to_string(),
        };

        let mut response = json!({
            "active": true,
            "sub": claims.sub,
            "client_id": client_id_from_aud,
            "aud": claims.aud,
            "scope": claims.scope,
            "token_type": token_type,
            "exp": claims.exp,
            "iat": claims.iat,
            "username": username,
        });

        // Include cnf claim for DPoP-bound tokens (RFC 9449)
        if let Some(cnf) = claims.cnf {
            if let Some(obj) = response.as_object_mut() {
                obj.insert("cnf".to_string(), cnf);
            }
        }

        // Include authorization_details for RAR tokens (RFC 9396)
        if let Some(auth_details) = claims.authorization_details {
            if let Some(obj) = response.as_object_mut() {
                obj.insert("authorization_details".to_string(), auth_details);
            }
        }

        Ok(Json(response))
    });

    result
}

/// Authenticate the client at the introspection endpoint.
async fn authenticate_client_introspect(
    state: &OidcState,
    params: &HashMap<String, String>,
    conn: &mut oidc_repository::Connection,
) -> Result<oidc_core::models::Client, OidcErrorResponse> {
    if let Some(assertion) = params.get("client_assertion") {
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

                let token_endpoint = format!("{}/oidc/introspect", state.issuer);
                let now = chrono::Utc::now().timestamp();
                JwtTokenService::verify_client_assertion(
                    assertion,
                    jwks,
                    &token_endpoint,
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

                let client_secret_bytes = state
                    .decrypt_client_encryption_key(encrypted_secret)
                    .map_err(|_| {
                        OidcErrorResponse::invalid_client("Failed to decrypt client secret")
                    })?;
                let client_secret = String::from_utf8(client_secret_bytes).map_err(|_| {
                    OidcErrorResponse::invalid_client("Invalid client secret encoding")
                })?;

                let token_endpoint = format!("{}/oidc/introspect", state.issuer);
                let now = chrono::Utc::now().timestamp();
                crate::tokens::jwt_service::verify_client_secret_jwt(
                    assertion,
                    &client_secret,
                    &token_endpoint,
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

    // --- client_secret_basic / client_secret_post ---
    let client_id = params
        .get("client_id")
        .ok_or_else(|| OidcErrorResponse::invalid_client("Missing client_id"))?;

    let _client_secret = params
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

    if let Some(ref hash) = client.client_secret_hash {
        if !state.hasher.verify(_client_secret, hash).unwrap_or(false) {
            return Err(OidcErrorResponse::invalid_client(
                "Invalid client credentials",
            ));
        }
    } else {
        return Err(OidcErrorResponse::invalid_client(
            "Public clients cannot introspect",
        ));
    }

    Ok(client)
}
