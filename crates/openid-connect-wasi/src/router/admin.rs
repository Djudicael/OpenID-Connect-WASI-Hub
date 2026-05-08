//! Admin static file serving routes.

use axum::Router;
use axum::response::Html;
use axum::routing::get;

use crate::state::AppState;

/// Build the admin sub-router.
pub fn router() -> Router<AppState> {
    // Serve admin UI static files from front/admin/
    // In production, these should be built and served from a CDN or nginx.
    Router::new()
        .route("/admin", get(admin_index_handler))
        .route("/admin/", get(admin_index_handler))
        .route("/admin/index.html", get(admin_index_handler))
}

async fn admin_index_handler() -> Html<&'static str> {
    Html(include_str!("../../../../front/admin/index.html"))
}
