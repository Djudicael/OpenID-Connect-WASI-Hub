//! WASI-first admin frontend server for the OpenID Connect Hub.
//! Serves the pre-built admin SPA entirely from compile-time embedded assets.

#![allow(missing_docs)]

use axum::Router;
use axum::body::Body;
use axum::extract::Path;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;

const ADMIN_INDEX_HTML: &str = include_str!("../../../front/admin/dist/index.html");
const ADMIN_BUNDLE_JS: &[u8] = include_bytes!("../../../front/admin/dist/js/index.js");
const ADMIN_BUNDLE_CSS: &[u8] = include_bytes!("../../../front/admin/dist/style/bundle.css");

pub fn app_router() -> Router {
    Router::new()
        .route("/", get(admin_index_handler))
        .route("/index.html", get(admin_index_handler))
        .route("/admin", get(admin_index_handler))
        .route("/admin/", get(admin_index_handler))
        .route("/admin/{*path}", get(admin_index_handler))
        .route("/js/{*path}", get(admin_javascript_handler))
        .route("/style/{*path}", get(admin_stylesheet_handler))
        .route("/{*path}", get(admin_spa_fallback_handler))
}

async fn admin_index_handler() -> Response {
    admin_index_response()
}

async fn admin_spa_fallback_handler(Path(path): Path<String>) -> Response {
    if is_admin_spa_path(&path) {
        admin_index_response()
    } else {
        not_found()
    }
}

async fn admin_javascript_handler(Path(path): Path<String>) -> Response {
    match path.as_str() {
        "index.js" => static_asset_response("text/javascript; charset=utf-8", ADMIN_BUNDLE_JS),
        _ => not_found(),
    }
}

async fn admin_stylesheet_handler(Path(path): Path<String>) -> Response {
    if is_admin_stylesheet_path(&path) {
        static_asset_response("text/css; charset=utf-8", ADMIN_BUNDLE_CSS)
    } else {
        not_found()
    }
}

fn admin_index_response() -> Response {
    let mut response = axum::response::Html(ADMIN_INDEX_HTML).into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    response
}

fn static_asset_response(content_type: &'static str, body: &'static [u8]) -> Response {
    let mut response = Response::new(Body::from(body));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static(content_type),
    );
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    response
}

fn not_found() -> Response {
    (StatusCode::NOT_FOUND, "not found").into_response()
}

fn is_admin_stylesheet_path(path: &str) -> bool {
    matches!(
        path.rsplit('/').next(),
        Some("main.css") | Some("bundle.css")
    ) || matches!(
        path.rsplit('/').next(),
        Some(file) if file.starts_with("bundle.") && file.ends_with(".css")
    )
}

fn is_admin_spa_path(path: &str) -> bool {
    let trimmed = path.trim_matches('/');
    if trimmed.is_empty() {
        return true;
    }

    let segments: Vec<&str> = trimmed
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect();
    if segments.is_empty() {
        return true;
    }

    if segments
        .last()
        .is_some_and(|segment| segment.contains('.') && *segment != ".well-known")
    {
        return false;
    }

    match segments[0] {
        "api" | "oidc" | ".well-known" | "health" | "js" | "style" => false,
        "realms" => {
            !(segments.len() >= 3 && matches!(segments[2], "login" | ".well-known" | "protocol"))
        }
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::{is_admin_spa_path, is_admin_stylesheet_path};

    #[test]
    fn admin_spa_fallback_skips_backend_and_file_routes() {
        assert!(is_admin_spa_path("users"));
        assert!(is_admin_spa_path("users/123"));
        assert!(is_admin_spa_path("admin/callback"));
        assert!(is_admin_spa_path("realms"));
        assert!(is_admin_spa_path("realms/123"));
        assert!(!is_admin_spa_path("api/users"));
        assert!(!is_admin_spa_path("oidc/authorize"));
        assert!(!is_admin_spa_path("health/live"));
        assert!(!is_admin_spa_path("realms/master/login"));
        assert!(!is_admin_spa_path(
            "realms/master/.well-known/openid-configuration"
        ));
        assert!(!is_admin_spa_path(
            "realms/master/protocol/openid-connect/token"
        ));
        assert!(!is_admin_spa_path("favicon.ico"));
        assert!(!is_admin_spa_path("style/broken.css"));
    }

    #[test]
    fn stylesheet_handler_accepts_bundled_aliases() {
        assert!(is_admin_stylesheet_path("main.css"));
        assert!(is_admin_stylesheet_path("bundle.css"));
        assert!(is_admin_stylesheet_path("bundle.bfd6f784.css"));
        assert!(!is_admin_stylesheet_path("theme.css"));
    }
}

#[cfg(target_arch = "wasm32")]
#[wstd_axum::http_server]
fn main() -> Router {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .try_init();

    app_router()
}
