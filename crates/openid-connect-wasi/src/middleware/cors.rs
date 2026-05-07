//! CORS middleware.

use tower_http::cors::CorsLayer;

/// Build the default CORS layer.
pub fn cors_layer() -> CorsLayer {
    CorsLayer::permissive()
}
