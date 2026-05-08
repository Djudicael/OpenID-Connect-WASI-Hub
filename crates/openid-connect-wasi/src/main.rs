//! Native server entry point for the OpenID Connect WASI Hub.

#[cfg(not(target_arch = "wasm32"))]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use openid_connect_wasi::state::AppState;

    tracing_subscriber::fmt::init();

    let state = AppState::from_env();

    openid_connect_wasi::server::starter::run_tcp(
        openid_connect_wasi::app_router(),
        &state.config.bind_address,
        state.config.port,
    )
    .await
}

#[cfg(target_arch = "wasm32")]
fn main() {
    // WASM entry point is in lib.rs via #[wstd_axum::http_server]
    panic!("native main should not be called on wasm32");
}
