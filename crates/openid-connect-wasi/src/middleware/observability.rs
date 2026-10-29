//! Opt-in request-local timing; aggregation belongs to the trusted hosting adapter.
use axum::{
    Router,
    extract::Request,
    middleware::{self, Next},
    response::Response,
};
use std::time::Instant;

pub const TIMING_HEADER: &str = "x-oidc-handler-duration-ns";

pub fn instrument(router: Router, enabled: bool) -> Router {
    if enabled {
        router.layer(middleware::from_fn(timing))
    } else {
        router
    }
}

async fn timing(mut request: Request, next: Next) -> Response {
    request.headers_mut().remove(TIMING_HEADER);
    let started = Instant::now();
    let mut response = next.run(request).await;
    // Bounded integer only. No request-derived labels, credentials or body inspection.
    if let Ok(value) = started.elapsed().as_nanos().to_string().parse() {
        response.headers_mut().insert(TIMING_HEADER, value);
    }
    response
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use axum::{body::Body, http::StatusCode, response::IntoResponse, routing::get};
    use tower::ServiceExt;

    #[tokio::test]
    async fn timing_is_opt_in_and_cannot_be_spoofed_or_forwarded_by_the_caller() {
        for enabled in [false, true] {
            let router = Router::new().route(
                "/health",
                get(move |request: Request| async move {
                    assert_eq!(request.headers().contains_key(TIMING_HEADER), !enabled);
                    let mut response = StatusCode::SERVICE_UNAVAILABLE.into_response();
                    if enabled {
                        response
                            .headers_mut()
                            .insert(TIMING_HEADER, "spoofed".parse().unwrap());
                    }
                    response
                }),
            );
            let response = instrument(router, enabled)
                .oneshot(
                    Request::builder()
                        .uri("/health")
                        .header(TIMING_HEADER, "untrusted")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
            if enabled {
                assert!(
                    response.headers()[TIMING_HEADER]
                        .to_str()
                        .unwrap()
                        .parse::<u64>()
                        .is_ok()
                );
            } else {
                assert!(!response.headers().contains_key(TIMING_HEADER));
            }
        }
    }
}
