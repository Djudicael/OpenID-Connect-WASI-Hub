use axum::Json;
use axum::extract::State;
use axum::http::HeaderMap;
use serde_json::{Value, json};
use std::collections::HashMap;

use oidc_core::traits::TokenService;
use oidc_repository::repositories::session_repo::SessionRepo;
use oidc_repository::repositories::user_repo::UserRepo;
use oidc_repository::with_transaction;

use crate::endpoints::client_auth::{
    authenticate_client_for_endpoint, detect_presented_client_auth_method,
    inject_basic_auth_credentials,
};
use crate::errors::OidcErrorResponse;
use crate::state::OidcState;

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
    headers: HeaderMap,
    axum::extract::Form(mut params): axum::extract::Form<HashMap<String, String>>,
) -> Result<Json<Value>, OidcErrorResponse> {
    let presented_auth_method = detect_presented_client_auth_method(&headers, &params)?;
    inject_basic_auth_credentials(&headers, &mut params)?;

    let token = params
        .get("token")
        .ok_or_else(|| OidcErrorResponse::invalid_request("Missing token"))?;

    let mut conn = state
        .connect()
        .await
        .map_err(|e| OidcErrorResponse::from_internal(e))?;

    let result = with_transaction!(conn, |e| OidcErrorResponse::from_internal(e), {
        // --- Client authentication ---
        let endpoint_uri = format!("{}/oidc/introspect", state.issuer);
        let client = authenticate_client_for_endpoint(
            &state,
            &params,
            &mut conn,
            presented_auth_method,
            &endpoint_uri,
        )
        .await?;

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
        let session = match SessionRepo
            .find_by_access_token_hash(&mut conn, &access_hash)
            .await
        {
            Ok(Some(s)) if !s.revoked => s,
            Ok(Some(_)) => return Ok(Json(json!({"active": false}))),
            Ok(None) => return Ok(Json(json!({"active": false}))),
            Err(e) => return Err(OidcErrorResponse::from_internal(e)),
        };

        if session.client_id != client.id {
            return Ok(Json(json!({"active": false})));
        }

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
