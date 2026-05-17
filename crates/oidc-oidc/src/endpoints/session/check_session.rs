//! Check Session Iframe endpoint.
//!
//! OIDC Session Management is intentionally not advertised right now because
//! the current runtime posture is not spec-compliant enough to support it
//! safely/interoperably (notably around cookie visibility and framing rules).
//! The route is kept only to fail explicitly until a compliant implementation
//! is added.

use axum::extract::Query;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

use crate::state::OidcState;

/// Query parameters for the check session iframe.
#[derive(Debug, Deserialize)]
pub struct CheckSessionParams {
    /// The RP's client_id.
    pub client_id: Option<String>,
    /// The RP's redirect URI.
    pub redirect_uri: Option<String>,
}

/// Check Session Iframe handler.
///
/// Returns `501 Not Implemented` until OIDC Session Management is implemented
/// in a spec-compliant way.
pub async fn check_session_handler(
    _state: OidcState,
    Query(_params): Query<CheckSessionParams>,
) -> Response {
    (
        axum::http::StatusCode::NOT_IMPLEMENTED,
        "OIDC Session Management is not currently supported",
    )
        .into_response()
}
