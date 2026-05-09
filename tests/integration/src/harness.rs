//! Test harness — manages a single PostgreSQL container for all integration tests.
//!
//! Uses `rustainers` with the Podman runner. The container is started once via
//! `tokio::sync::OnceCell` and reused across all test modules.

use rustainers::runner::Runner;
use rustainers::ImageName;
use tokio::sync::OnceCell;

const DB_NAME: &str = "oidc_hub_test";
const DB_USER: &str = "postgres";
const DB_PASSWORD: &str = "postgres";

/// Global singleton — container + connection URL.
static HARNESS: OnceCell<(rustainers::Container<rustainers::images::GenericImage>, String)> = OnceCell::const_new();

/// Initialise the shared PostgreSQL container.
async fn init_harness() -> (rustainers::Container<rustainers::images::GenericImage>, String) {
    let image_name = ImageName::new_with_tag("docker.io/library/postgres", "16-alpine");
    let mut image = rustainers::images::GenericImage::new(image_name);
    image.add_env_var("POSTGRES_DB", DB_NAME);
    image.add_env_var("POSTGRES_USER", DB_USER);
    image.add_env_var("POSTGRES_PASSWORD", DB_PASSWORD);
    image.add_port_mapping(5432);

    let podman = Runner::podman().expect("Failed to create Podman runner");
    let container = podman
        .start(image)
        .await
        .expect("Failed to start PostgreSQL container");

    // Get the host-mapped port
    let host_port = container
        .host_port(5432)
        .await
        .expect("Failed to get host port");

    let url = format!(
        "postgresql://{DB_USER}:{DB_PASSWORD}@localhost:{host_port}/{DB_NAME}"
    );

    // Wait for PostgreSQL to be ready
    wait_for_postgres(&url).await;

    // Run migrations inline
    run_migrations(&url).await.expect("migrations failed");

    tracing::info!("Test harness ready: {}", url);
    (container, url)
}

/// Poll the database until it accepts connections.
async fn wait_for_postgres(url: &str) {
    let config = wasi_pg_client::Config::from_uri(url).expect("invalid URL");
    let start = std::time::Instant::now();
    let timeout = std::time::Duration::from_secs(60);

    loop {
        if start.elapsed() > timeout {
            panic!("PostgreSQL did not become ready within 60s");
        }

        match wasi_pg_client::Connection::connect(&config).await {
            Ok(mut conn) => {
                match conn.query("SELECT 1").await {
                    Ok(_) => {
                        tracing::info!("PostgreSQL is ready");
                        break;
                    }
                    Err(e) => {
                        tracing::debug!("query failed: {e}, retrying...");
                        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                    }
                }
            }
            Err(e) => {
                tracing::debug!("connect failed: {e}, retrying...");
                tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
            }
        }
    }
}

/// Run migrations inline (same logic as oidc-migrate).
async fn run_migrations(url: &str) -> Result<(), Box<dyn std::error::Error>> {
    let config = wasi_pg_client::Config::from_uri(url)?;
    let mut conn = wasi_pg_client::Connection::connect(&config).await?;

    let migrations_dir = std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../../migrations/postgresql"));
    if !migrations_dir.exists() {
        return Err(format!("migrations directory not found: {}", migrations_dir.display()).into());
    }

    // Ensure migrations tracking table exists
    conn.query(r#"
        CREATE TABLE IF NOT EXISTS _migrations (
            id SERIAL PRIMARY KEY,
            filename TEXT NOT NULL UNIQUE,
            applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    "#).await?;

    let mut entries: Vec<_> = std::fs::read_dir(migrations_dir)?
        .filter_map(|e| e.ok())
        .filter(|e| {
            let name = e.file_name();
            let s = name.to_string_lossy();
            s.ends_with(".sql")
        })
        .collect();

    entries.sort_by_key(|e| e.file_name());

    for entry in entries {
        let filename = entry.file_name().to_string_lossy().to_string();

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
        let sql = std::fs::read_to_string(&path)?;

        tracing::info!("apply {filename}");
        conn.query(&sql).await.map_err(|e| {
            format!("failed to apply {}: {}", filename, e)
        })?;

        conn.execute_params(
            "INSERT INTO _migrations (filename) VALUES ($1)",
            &[&filename],
        ).await?;

        tracing::info!("applied {filename} ok");
    }

    tracing::info!("migrations complete");
    Ok(())
}

/// Get the shared database URL, initialising the container if necessary.
pub async fn database_url() -> String {
    let (_, url) = HARNESS.get_or_init(init_harness).await;
    url.clone()
}

/// Open a fresh connection to the shared test database.
pub async fn test_conn() -> oidc_repository::connection::Connection {
    let url = database_url().await;
    let config = wasi_pg_client::Config::from_uri(&url).expect("invalid database URL");
    let pg_conn = wasi_pg_client::Connection::connect(&config)
        .await
        .expect("failed to connect to test database");
    oidc_repository::connection::Connection::from_pg_client(pg_conn)
}

/// Clean all data tables (keep `_migrations`).
pub async fn clean_database(
    conn: &mut oidc_repository::connection::Connection,
) -> Result<(), oidc_core::OidcError> {
    let tables = [
        "audit_events",
        "mls_commits",
        "mls_members",
        "mls_key_packages",
        "mls_groups",
        "authorization_codes",
        "sessions",
        "api_keys",
        "signing_keys",
        "clients",
        "users",
        "realms",
    ];
    for table in &tables {
        conn.execute(&format!("DELETE FROM {}", table))
            .await
            .map_err(|e| oidc_core::OidcError::Internal(e.to_string()))?;
    }
    Ok(())
}
