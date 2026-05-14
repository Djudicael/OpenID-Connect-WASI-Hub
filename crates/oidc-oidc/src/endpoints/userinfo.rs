//! UserInfo endpoint handler.

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::json;

use oidc_core::traits::TokenService;
use oidc_repository::repositories::session_repo::SessionRepo;
use oidc_repository::repositories::user_repo::UserRepo;

use crate::state::OidcState;

/// UserInfo endpoint handler.
/// Returns claims scoped to the access token's granted scopes.
/// Per RFC 6750, returns 401 with `WWW-Authenticate: Bearer error="invalid_token"`
/// when the token is missing or invalid.
pub async fn userinfo_handler(
    State(state): State<OidcState>,
    authorization: Option<axum::http::HeaderValue>,
) -> Response {
    let token = match extract_bearer_token(authorization) {
        Ok(t) => t,
        Err(()) => return unauthorized_response(),
    };

    let subject = match state.token_service.verify_access_token(&token).await {
        Ok(sub) => sub,
        Err(_) => return unauthorized_response(),
    };

    let user_id = match subject.parse() {
        Ok(id) => id,
        Err(_) => return unauthorized_response(),
    };

    let mut conn = match state.connect().await {
        Ok(c) => c,
        Err(_) => return internal_error_response(),
    };

    // Look up the session to get granted scopes
    let access_hash = oidc_core::utils::sha2_256_hex(&token);
    let session = match SessionRepo
        .find_by_access_token_hash(&mut conn, &access_hash)
        .await
    {
        Ok(Some(s)) => s,
        Ok(None) => return unauthorized_response(),
        Err(_) => return internal_error_response(),
    };

    if session.revoked {
        return unauthorized_response();
    }

    let user = match UserRepo.find_by_id(&mut conn, user_id).await {
        Ok(Some(u)) => u,
        Ok(None) => return unauthorized_response(),
        Err(_) => return internal_error_response(),
    };

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
            if let Some(ref name) = user.middle_name {
                obj.insert("middle_name".to_string(), json!(name));
            }
            if let Some(ref name) = user.username {
                obj.insert("name".to_string(), json!(name));
            }
            if let Some(ref v) = user.nickname {
                obj.insert("nickname".to_string(), json!(v));
            }
            if let Some(ref v) = user.preferred_username {
                obj.insert("preferred_username".to_string(), json!(v));
            }
            if let Some(ref v) = user.profile {
                obj.insert("profile".to_string(), json!(v));
            }
            if let Some(ref v) = user.picture {
                obj.insert("picture".to_string(), json!(v));
            }
            if let Some(ref v) = user.website {
                obj.insert("website".to_string(), json!(v));
            }
            if let Some(ref v) = user.gender {
                obj.insert("gender".to_string(), json!(v));
            }
            if let Some(ref v) = user.birthdate {
                obj.insert("birthdate".to_string(), json!(v));
            }
            if let Some(ref v) = user.zoneinfo {
                obj.insert("zoneinfo".to_string(), json!(v));
            }
            obj.insert("locale".to_string(), json!(user.locale));
            obj.insert("updated_at".to_string(), json!(user.updated_at.timestamp()));
        }
    }

    if scopes.contains("phone") {
        if let Some(obj) = claims.as_object_mut() {
            if let Some(ref v) = user.phone_number {
                obj.insert("phone_number".to_string(), json!(v));
            }
            if let Some(v) = user.phone_number_verified {
                obj.insert("phone_number_verified".to_string(), json!(v));
            }
        }
    }

    Json(claims).into_response()
}

/// Build a 401 Unauthorized response with the required `WWW-Authenticate` header.
///
/// Per RFC 6750 §3, the error response MUST include:
/// `WWW-Authenticate: Bearer error="invalid_token"`
fn unauthorized_response() -> Response {
    let mut response = (
        StatusCode::UNAUTHORIZED,
        axum::Json(json!({
            "error": "invalid_token",
            "error_description": "The access token is missing, invalid, or expired."
        })),
    )
        .into_response();

    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static("Bearer error=\"invalid_token\""),
    );

    response
}

/// Build a 500 Internal Server Error response.
fn internal_error_response() -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        axum::Json(json!({
            "error": "server_error",
            "error_description": "An internal error occurred."
        })),
    )
        .into_response()
}

fn extract_bearer_token(header: Option<axum::http::HeaderValue>) -> Result<String, ()> {
    let header = header.ok_or(())?;
    let header_str = header.to_str().map_err(|_| ())?;
    let token = header_str
        .strip_prefix("Bearer ")
        .or_else(|| header_str.strip_prefix("bearer "))
        .ok_or(())?;
    Ok(token.to_string())
}
