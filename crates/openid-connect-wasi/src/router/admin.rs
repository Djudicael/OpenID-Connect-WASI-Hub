//! Admin static file serving routes.

use axum::Router;

/// Build the admin sub-router (static files).
pub fn router() -> Router {
    // TODO: serve static files from front/admin/dist
    Router::new()
}
