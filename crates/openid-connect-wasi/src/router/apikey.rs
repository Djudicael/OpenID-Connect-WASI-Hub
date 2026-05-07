//! API key routes.

use axum::routing::{delete, get, post};
use axum::Router;

/// Build the API key sub-router.
pub fn router() -> Router {
    Router::new()
        .route("/api/keys", get(oidc_apikey::endpoints::list_keys))
        .route("/api/keys", post(oidc_apikey::endpoints::create_key))
        .route("/api/keys/:id", delete(oidc_apikey::endpoints::revoke_key))
}
