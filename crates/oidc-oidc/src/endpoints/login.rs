//! Direct username/password login endpoint (first-party apps).

use axum::Json;
use axum::extract::State;
use axum::http::header::SET_COOKIE;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};

use crate::errors::{OidcErrorResponse, from_oidc_error};
use crate::flows::password::PasswordFlow;
use crate::session_cookie;
use crate::state::OidcState;

/// Login request body.
#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
    pub client_id: Option<String>,
    /// Optional realm name for authentication.
    /// When omitted, defaults to "master" (backward-compatible).
    pub realm: Option<String>,
}

/// Successful login response.
#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub id_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub user: UserInfo,
}

/// Public user info.
#[derive(Debug, Serialize)]
pub struct UserInfo {
    pub id: String,
    pub email: String,
    pub username: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
}

/// Direct login handler — validates credentials and returns tokens.
///
/// On success, also sets a `Set-Cookie` header with an HMAC-protected
/// session cookie for browser-based SSO.
pub async fn login_handler(
    State(state): State<OidcState>,
    Json(req): Json<LoginRequest>,
) -> Result<Response, OidcErrorResponse> {
    let result = PasswordFlow::execute(
        &state,
        &req.email,
        &req.password,
        req.client_id.as_deref(),
        req.realm.as_deref(),
    )
    .await
    .map_err(|e| from_oidc_error(&e))?;

    // Build the JSON response body
    let body = Json(LoginResponse {
        access_token: result.access_token,
        refresh_token: result.refresh_token,
        id_token: result.id_token,
        token_type: result.token_type,
        expires_in: result.expires_in,
        user: UserInfo {
            id: result.user_id,
            email: result.user_email,
            username: result.user_username,
            given_name: result.user_given_name,
            family_name: result.user_family_name,
        },
    });

    // Set the session cookie
    let encryption_key = state
        .decode_encryption_key()
        .map_err(|e| from_oidc_error(&e))?;
    let cookie_header = session_cookie::session_cookie_header(&result.session_id, &encryption_key);

    let mut response = body.into_response();
    response.headers_mut().insert(
        SET_COOKIE,
        cookie_header
            .parse()
            .expect("session cookie header should be valid"),
    );

    Ok(response)
}
