//! UserInfo endpoint handler.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use serde_json::{Value, json};

use oidc_core::traits::TokenService;
use oidc_repository::repositories::session_repo::SessionRepo;
use oidc_repository::repositories::user_repo::UserRepo;

use crate::state::OidcState;

/// UserInfo endpoint handler.
/// Returns claims scoped to the access token's granted scopes.
pub async fn userinfo_handler(
    State(state): State<OidcState>,
    authorization: Option<axum::http::HeaderValue>,
) -> Result<Json<Value>, StatusCode> {
    let token = extract_bearer_token(authorization)?;

    let subject = state
        .token_service
        .verify_access_token(&token)
        .await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    let user_id = subject.parse().map_err(|_| StatusCode::UNAUTHORIZED)?;

    let mut conn = state
        .connect()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Look up the session to get granted scopes
    let access_hash = oidc_core::utils::sha2_256_hex(&token);
    let session = SessionRepo
        .find_by_access_token_hash(&mut conn, &access_hash)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let user = UserRepo
        .find_by_id(&mut conn, user_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let scopes: std::collections::HashSet<String> = session.scope.into_iter().collect();

    let mut claims = json!({
        "sub": user.id.to_string(),
    });

    if scopes.contains("email") {
        if let Some(obj) = claims.as_object_mut() {
            obj.insert("email".to_string(), json!(user.email));
            obj.insert("email_verified".to_string(), json!(user.email_verified));
        }
    }

    if scopes.contains("profile") {
        if let Some(obj) = claims.as_object_mut() {
            if let Some(ref name) = user.given_name {
                obj.insert("given_name".to_string(), json!(name));
            }
            if let Some(ref name) = user.family_name {
                obj.insert("family_name".to_string(), json!(name));
            }
            if let Some(ref name) = user.username {
                obj.insert("name".to_string(), json!(name));
            }
        }
    }

    Ok(Json(claims))
}

fn extract_bearer_token(header: Option<axum::http::HeaderValue>) -> Result<String, StatusCode> {
    let header = header.ok_or(StatusCode::UNAUTHORIZED)?;
    let header_str = header.to_str().map_err(|_| StatusCode::UNAUTHORIZED)?;
    let token = header_str
        .strip_prefix("Bearer ")
        .or_else(|| header_str.strip_prefix("bearer "))
        .ok_or(StatusCode::UNAUTHORIZED)?;
    Ok(token.to_string())
}
