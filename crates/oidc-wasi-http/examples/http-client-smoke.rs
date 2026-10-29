//! Runtime probe for incoming bodies, outbound P3 HTTP, and response limits.

#[cfg(target_arch = "wasm32")]
mod component {
    use axum::body::{Body, Bytes};
    use axum::extract::Path;
    use axum::http::{Response, StatusCode};
    use axum::routing::post;

    wasip3::http::service::export!(Probe);

    struct Probe;

    impl wasip3::exports::http::handler::Guest for Probe {
        async fn handle(
            request: wasip3::http::types::Request,
        ) -> Result<wasip3::http::types::Response, wasip3::http::types::ErrorCode> {
            let router = axum::Router::new().route("/{mode}", post(proxy));
            oidc_wasi_http::handle(router, request).await
        }
    }

    async fn proxy(
        Path(mode): Path<String>,
        body: Bytes,
    ) -> Result<Response<Body>, (StatusCode, String)> {
        let upstream = std::env::var("OIDC_SMOKE_HTTP_URL").map_err(bad_gateway)?;
        let request = oidc_wasi_http::Request::post(format!("{upstream}/{mode}"))
            .header("authorization", "Bearer runtime-smoke")
            .body(Body::from(body))
            .map_err(bad_gateway)?;
        let response = oidc_wasi_http::send(request).await.map_err(bad_gateway)?;
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = oidc_wasi_http::read_body(response)
            .await
            .map_err(bad_gateway)?;
        let mut response = Response::new(Body::from(bytes));
        *response.status_mut() = status;
        *response.headers_mut() = headers;
        Ok(response)
    }

    fn bad_gateway(error: impl std::fmt::Display) -> (StatusCode, String) {
        (StatusCode::BAD_GATEWAY, error.to_string())
    }
}
