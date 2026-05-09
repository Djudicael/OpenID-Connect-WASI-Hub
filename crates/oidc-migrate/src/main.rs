//! OIDC migration runner — native only.
//!
//! Reads SQL files from `migrations/postgresql/` and applies them in order.
//! Usage: OIDC_DATABASE_URL=postgresql://... cargo run -p oidc-migrate

use std::fs;
use std::path::Path;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let database_url = std::env::var("OIDC_DATABASE_URL")
        .unwrap_or_else(|_| "postgresql://localhost/oidc_hub".into());

    let config = wasi_pg_client::Config::from_uri(&database_url)?;
    let mut conn = wasi_pg_client::Connection::connect(&config).await?;

    let migrations_dir = Path::new("migrations/postgresql");
    if !migrations_dir.exists() {
        anyhow::bail!(
            "migrations directory not found: {}",
            migrations_dir.display()
        );
    }

    // Ensure migrations tracking table exists
    conn.query(
        r#"
        CREATE TABLE IF NOT EXISTS _migrations (
            id SERIAL PRIMARY KEY,
            filename TEXT NOT NULL UNIQUE,
            applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    "#,
    )
    .await?;

    let mut entries: Vec<_> = fs::read_dir(migrations_dir)?
        .filter_map(|e| e.ok())
        .filter(|e| {
            let name = e.file_name();
            let s = name.to_string_lossy();
            s.ends_with(".sql")
        })
        .collect();

    // Sort by the numeric prefix (V1, V2, ..., V10, ...) not alphabetically
    // (alphabetical would put V10 before V2).
    entries.sort_by_key(|e| {
        let name = e.file_name().to_string_lossy().to_string();
        name.split_once('_')
            .and_then(|(prefix, _)| prefix.strip_prefix('V'))
            .and_then(|num| num.parse::<u32>().ok())
            .unwrap_or(0)
    });

    for entry in entries {
        let filename = entry.file_name().to_string_lossy().to_string();

        // Check if already applied
        let check = conn
            .query_params(
                "SELECT 1 FROM _migrations WHERE filename = $1",
                &[&filename],
            )
            .await?;
        if !check.into_rows().is_empty() {
            tracing::info!("skip {filename} (already applied)");
            continue;
        }

        let path = entry.path();
        let sql = fs::read_to_string(&path)?;

        tracing::info!("apply {filename}");
        conn.query(&sql)
            .await
            .map_err(|e| anyhow::anyhow!("failed to apply {}: {}", filename, e))?;

        conn.execute_params(
            "INSERT INTO _migrations (filename) VALUES ($1)",
            &[&filename],
        )
        .await?;

        tracing::info!("applied {filename} ok");
    }

    tracing::info!("migrations complete");
    Ok(())
}
