//! Authentication middleware.

use axum::body::Body;
use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::Response;
use oidc_core::traits::TokenService;

use crate::state::AppState;

/// Middleware that extracts and validates authentication.
///
/// If a valid `Authorization: Bearer <token>` header is present, the token
/// is verified and the subject is inserted into request extensions.
/// Invalid or missing tokens are logged but the request is still allowed
/// through so that downstream handlers can decide whether authentication
/// is required.
pub async fn auth_middleware(
    State(state): State<AppState>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    if let Some(auth_header) = request.headers().get(axum::http::header::AUTHORIZATION) {
        if let Ok(auth_str) = auth_header.to_str() {
            if let Some(token) = auth_str.strip_prefix("Bearer ") {
                match state.token_service.verify_access_token(token).await {
                    Ok(subject) => {
                        request.extensions_mut().insert(subject);
                    }
                    Err(e) => {
                        tracing::warn!("Bearer token verification failed: {}", e);
                    }
                }
            } else {
                tracing::warn!("Authorization header does not start with 'Bearer '");
            }
        } else {
            tracing::warn!("Authorization header contains invalid UTF-8");
        }
    }

    next.run(request).await
}
