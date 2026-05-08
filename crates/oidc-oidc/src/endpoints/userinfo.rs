use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use serde_json::{Value, json};

use oidc_core::traits::TokenService;
use oidc_repository::repositories::user_repo::UserRepo;

use crate::state::OidcState;

/// UserInfo endpoint handler.
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

    let mut conn = state.connect().await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let user = UserRepo
        .find_by_id(&mut conn, user_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    Ok(Json(json!({
        "sub": user.id.to_string(),
        "email": user.email,
        "email_verified": user.email_verified,
        "given_name": user.given_name,
        "family_name": user.family_name,
        "name": user.username,
    })))
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
