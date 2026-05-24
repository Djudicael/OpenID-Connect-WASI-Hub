//! Native entry point for the admin frontend WASI crate.

#[cfg(not(target_arch = "wasm32"))]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use std::env;

    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .try_init();

    let bind_address =
        env::var("OIDC_ADMIN_SERVER_BIND_ADDRESS").unwrap_or_else(|_| "0.0.0.0".to_string());
    let port = env::var("OIDC_ADMIN_SERVER_PORT")
        .ok()
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(3001);

    let listener = tokio::net::TcpListener::bind(format!("{}:{}", bind_address, port)).await?;
    tracing::info!("Admin frontend listening on {}:{}", bind_address, port);
    axum::serve(listener, oidc_admin_wasi::app_router()).await?;
    Ok(())
}

#[cfg(target_arch = "wasm32")]
fn main() {
    panic!("native main should not be called on wasm32");
}
