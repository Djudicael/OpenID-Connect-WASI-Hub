//! Direct username/password login endpoint (first-party apps).

use axum::Json;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::http::header::{AUTHORIZATION, SET_COOKIE};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};

use crate::endpoints::mfa::LoginMfaProof;
use crate::errors::{OidcErrorResponse, from_oidc_error};
use crate::flows::password::{PasswordFlow, PasswordFlowOutcome};
use crate::session_cookie;
use crate::state::OidcState;
use oidc_core::OidcError;

/// Login request body.
#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
    pub client_id: Option<String>,
    /// Optional realm name for authentication.
    /// When omitted, defaults to "master" (backward-compatible).
    pub realm: Option<String>,
    #[serde(default)]
    pub requested_scopes: Vec<String>,
    #[serde(default)]
    pub requested_acr_values: Vec<String>,
    #[serde(flatten)]
    pub mfa: Option<LoginMfaProof>,
}

#[derive(Debug, Deserialize)]
pub struct KerberosLoginRequest {
    pub client_id: Option<String>,
    pub realm: Option<String>,
    #[serde(default)]
    pub requested_scopes: Vec<String>,
    #[serde(default)]
    pub requested_acr_values: Vec<String>,
    #[serde(flatten)]
    pub mfa: Option<LoginMfaProof>,
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
    execute_login(&state, &req, None).await
}

/// Browser-integrated Kerberos login using an HTTP Negotiate token.
pub async fn kerberos_login_handler(
    State(state): State<OidcState>,
    headers: HeaderMap,
    Json(request): Json<KerberosLoginRequest>,
) -> Response {
    let Some(token) = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Negotiate "))
        .filter(|value| !value.trim().is_empty())
    else {
        return kerberos_challenge();
    };
    let login = LoginRequest {
        email: String::new(),
        password: String::new(),
        client_id: request.client_id,
        realm: request.realm,
        requested_scopes: request.requested_scopes,
        requested_acr_values: request.requested_acr_values,
        mfa: request.mfa,
    };
    match execute_login(&state, &login, Some(token)).await {
        Ok(response) => response,
        Err(_) => kerberos_challenge(),
    }
}

fn kerberos_challenge() -> Response {
    let mut response = (
        axum::http::StatusCode::UNAUTHORIZED,
        Json(serde_json::json!({"error":"invalid_credentials"})),
    )
        .into_response();
    response.headers_mut().insert(
        axum::http::header::WWW_AUTHENTICATE,
        axum::http::HeaderValue::from_static("Negotiate"),
    );
    response
}

async fn execute_login(
    state: &OidcState,
    req: &LoginRequest,
    kerberos_token: Option<&str>,
) -> Result<Response, OidcErrorResponse> {
    let result = PasswordFlow::execute(
        state,
        &req.email,
        &req.password,
        req.client_id.as_deref(),
        req.realm.as_deref(),
        None, // DPoP not supported at the login endpoint
        req.mfa.as_ref(),
        &req.requested_scopes,
        &req.requested_acr_values,
        kerberos_token,
    )
    .await
    .map_err(|e| from_oidc_error(&e))?;

    let result = match result {
        PasswordFlowOutcome::MfaRequired(challenge) => {
            return Ok((
                axum::http::StatusCode::ACCEPTED,
                Json(serde_json::json!({
                    "mfa_required": true,
                    "challenge": challenge
                })),
            )
                .into_response());
        }
        PasswordFlowOutcome::RequiredActions(challenge) => {
            return Ok((
                axum::http::StatusCode::ACCEPTED,
                Json(serde_json::json!({
                    "required_actions_pending": true,
                    "required_actions": challenge.required_actions,
                    "action_token": challenge.action_token,
                    "expires_in": challenge.expires_in,
                    "terms": challenge.terms,
                    "user_email": challenge.user_email,
                    "realm": challenge.realm,
                })),
            )
                .into_response());
        }
        PasswordFlowOutcome::MfaRejected => {
            return Ok(from_oidc_error(&OidcError::AuthenticationFailed(
                "MFA verification failed".into(),
            ))
            .into_response());
        }
        PasswordFlowOutcome::Authenticated(result) => result,
    };

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

    let cookie_value = cookie_header.parse().map_err(|e| {
        from_oidc_error(&OidcError::Internal(format!(
            "failed to parse session cookie header: {e}"
        )))
    })?;
    let mut response = body.into_response();
    response.headers_mut().insert(SET_COOKIE, cookie_value);

    Ok(response)
}
