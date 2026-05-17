use axum::Json;
use axum::extract::State;
use axum::http::HeaderMap;
use serde_json::{Value, json};
use std::collections::HashMap;

use oidc_repository::repositories::session_repo::SessionRepo;
use oidc_repository::with_transaction;

use crate::endpoints::client_auth::{
    authenticate_client_for_endpoint, detect_presented_client_auth_method,
    inject_basic_auth_credentials,
};
use crate::errors::OidcErrorResponse;
use crate::state::OidcState;

/// Token revocation endpoint handler.
/// Requires client authentication. Supports both access tokens and refresh tokens.
pub async fn revoke_handler(
    State(state): State<OidcState>,
    headers: HeaderMap,
    axum::extract::Form(mut params): axum::extract::Form<HashMap<String, String>>,
) -> Result<Json<Value>, OidcErrorResponse> {
    let presented_auth_method = detect_presented_client_auth_method(&headers, &params)?;
    inject_basic_auth_credentials(&headers, &mut params)?;

    let token = params
        .get("token")
        .ok_or_else(|| OidcErrorResponse::invalid_request("Missing token"))?;

    let token_type_hint = params.get("token_type_hint").map(|s| s.as_str());

    let mut conn = state
        .connect()
        .await
        .map_err(|e| OidcErrorResponse::from_internal(e))?;

    with_transaction!(conn, |e| OidcErrorResponse::from_internal(e), {
        // --- Client authentication ---
        let endpoint_uri = state.revocation_endpoint_uri();
        let client = authenticate_client_for_endpoint(
            &state,
            &params,
            &mut conn,
            presented_auth_method,
            &endpoint_uri,
        )
        .await?;

        let token_hash = oidc_core::utils::sha2_256_hex(token);

        // Try refresh token first if hinted, otherwise try access token
        if token_type_hint == Some("refresh_token") {
            if let Ok(Some(session)) = SessionRepo
                .find_by_refresh_token_hash(&mut conn, &token_hash)
                .await
            {
                if session.client_id == client.id {
                    let _ = SessionRepo.revoke(&mut conn, session.id).await;
                }
                return Ok(Json(json!({})));
            }
        }

        // Try as access token
        if let Ok(Some(session)) = SessionRepo
            .find_by_access_token_hash(&mut conn, &token_hash)
            .await
        {
            if session.client_id == client.id {
                let _ = SessionRepo.revoke(&mut conn, session.id).await;
            }
            return Ok(Json(json!({})));
        }

        // Also try as refresh token if not already tried
        if token_type_hint != Some("refresh_token") {
            if let Ok(Some(session)) = SessionRepo
                .find_by_refresh_token_hash(&mut conn, &token_hash)
                .await
            {
                if session.client_id == client.id {
                    let _ = SessionRepo.revoke(&mut conn, session.id).await;
                }
                return Ok(Json(json!({})));
            }
        }

        // Per RFC 7009, return 200 even if token not found
        Ok(Json(json!({})))
    })
}
