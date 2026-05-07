//! OIDC protocol routes.

use axum::routing::{get, post};
use axum::Router;

/// Build the OIDC sub-router.
pub fn router() -> Router {
    Router::new()
        .route("/.well-known/openid-configuration", get(oidc_oidc::discovery_handler))
        .route("/oidc/jwks", get(oidc_oidc::jwks_handler))
        .route("/oidc/authorize", get(oidc_oidc::endpoints::authorize::authorize_handler))
        .route("/oidc/token", post(oidc_oidc::endpoints::token::token_handler))
        .route("/oidc/userinfo", get(oidc_oidc::endpoints::userinfo::userinfo_handler))
        .route("/oidc/introspect", post(oidc_oidc::endpoints::introspect::introspect_handler))
        .route("/oidc/revoke", post(oidc_oidc::endpoints::revoke::revoke_handler))
}
