//! API key Axum extractor and middleware.

use axum::extract::FromRequestParts;

/// Extracted API key authentication.
pub struct ApiKeyAuth;

impl<S: Sync> FromRequestParts<S> for ApiKeyAuth {
    type Rejection = axum::http::StatusCode;

    async fn from_request_parts(
        _parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        // TODO: implement extraction
        Ok(Self)
    }
}
