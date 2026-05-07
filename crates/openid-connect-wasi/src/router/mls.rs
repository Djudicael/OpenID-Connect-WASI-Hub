//! MLS routes.

use axum::routing::post;
use axum::Router;

/// Build the MLS sub-router.
pub fn router() -> Router {
    Router::new()
        .route("/api/mls/groups", post(oidc_mls::endpoints::create_group))
        .route("/api/mls/key-packages", post(oidc_mls::endpoints::upload_key_package))
        .route("/api/mls/groups/:id/commits", post(oidc_mls::endpoints::send_commit))
}
