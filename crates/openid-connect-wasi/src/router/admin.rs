//! Admin static file serving routes.

use axum::Router;

use crate::state::AppState;

/// Build the admin sub-router (static files).
pub fn router() -> Router<AppState> {
    // TODO: serve static files from front/admin/dist
    Router::new()
}
