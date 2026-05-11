//! Test harness — manages a single PostgreSQL container for all integration tests.
//!
//! Uses `rustainers` with the Podman runner. The container is started once via
//! `tokio::sync::OnceCell` and reused across all test modules.

use rustainers::ImageName;
use rustainers::runner::Runner;
use tokio::sync::OnceCell;

const DB_NAME: &str = "oidc_hub_test";
const DB_USER: &str = "postgres";
const DB_PASSWORD: &str = "postgres";

/// Global singleton — container + connection URL.
static HARNESS: OnceCell<(
    rustainers::Container<rustainers::images::GenericImage>,
    String,
)> = OnceCell::const_new();

/// Initialise the shared PostgreSQL container.
async fn init_harness() -> (
    rustainers::Container<rustainers::images::GenericImage>,
    String,
) {
    // Initialise tracing subscriber (idempotent — safe to call multiple times)
    let _ = tracing_subscriber::FmtSubscriber::builder()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .try_init();

    let image_name = ImageName::new_with_tag("docker.io/library/postgres", "16-alpine");
    let mut image = rustainers::images::GenericImage::new(image_name);
    image.add_env_var("POSTGRES_DB", DB_NAME);
    image.add_env_var("POSTGRES_USER", DB_USER);
    image.add_env_var("POSTGRES_PASSWORD", DB_PASSWORD);
    image.add_port_mapping(5432);

    // Clean up stale PostgreSQL test containers from previous runs.
    // The OnceCell is per-process, so old containers from crashed runs
    // would otherwise accumulate and waste resources.
    let podman = Runner::podman().expect("Failed to create Podman runner");
    {
        let output = tokio::process::Command::new("podman")
            .args([
                "rm",
                "-fa",
                "--filter",
                "label=org.rustainers.image=docker.io/library/postgres:16-alpine",
            ])
            .output()
            .await;
        match output {
            Ok(o) if o.status.success() => tracing::debug!("cleaned up stale containers"),
            Ok(o) => tracing::debug!("cleanup stderr: {}", String::from_utf8_lossy(&o.stderr)),
            Err(e) => tracing::debug!("cleanup failed: {e}"),
        }
    }

    let container = podman
        .start(image)
        .await
        .expect("Failed to start PostgreSQL container");

    // Get the host-mapped port
    let host_port = container
        .host_port(5432)
        .await
        .expect("Failed to get host port");

    let url = format!("postgresql://{DB_USER}:{DB_PASSWORD}@localhost:{host_port}/{DB_NAME}");

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
            Ok(mut conn) => match conn.query("SELECT 1").await {
                Ok(_) => {
                    tracing::info!("PostgreSQL is ready");
                    let _ = conn.close().await;
                    break;
                }
                Err(e) => {
                    tracing::debug!("query failed: {e}, retrying...");
                    let _ = conn.close().await;
                    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                }
            },
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

    let migrations_dir = std::path::Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../migrations/postgresql"
    ));
    if !migrations_dir.exists() {
        return Err(format!(
            "migrations directory not found: {}",
            migrations_dir.display()
        )
        .into());
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

    let mut entries: Vec<_> = std::fs::read_dir(migrations_dir)?
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
        conn.batch_execute(&sql)
            .await
            .map_err(|e| format!("failed to apply {}: {}", filename, e))?;

        conn.execute_params(
            "INSERT INTO _migrations (filename) VALUES ($1)",
            &[&filename],
        )
        .await?;

        tracing::info!("applied {filename} ok");
    }

    tracing::info!("migrations complete");

    // Gracefully close the migration connection.
    let _ = conn.close().await;

    Ok(())
}

/// Get the shared database URL, initialising the container if necessary.
pub async fn database_url() -> String {
    let (_, url) = HARNESS.get_or_init(init_harness).await;
    url.clone()
}

/// Open a fresh connection to the shared test database.
///
/// The connection automatically starts a transaction.  When this
/// connection is dropped, the TCP socket closes which implicitly rolls
/// back the transaction on the server side.  Every test that uses this
/// gets its own isolated workspace — no `clean_database` needed.
///
/// Use this for **unit-style** DB/repo tests that do all their work
/// through this single connection.
pub async fn test_conn() -> oidc_repository::connection::Connection {
    let url = database_url().await;
    let config = wasi_pg_client::Config::from_uri(&url).expect("invalid database URL");
    let pg_conn = wasi_pg_client::Connection::connect(&config)
        .await
        .expect("failed to connect to test database");
    let mut conn = oidc_repository::connection::Connection::from_pg_client(pg_conn);
    conn.begin()
        .await
        .expect("failed to begin test transaction");
    conn
}

/// Open a connection **without** a transaction.
///
/// Use this for **HTTP integration** tests where the app under test
/// gets its own database connection and must be able to see seeded
/// data.  Callers must pair this with [`clean_database`] to reset
/// state between tests.
pub async fn test_conn_no_tx() -> oidc_repository::connection::Connection {
    let url = database_url().await;
    let config = wasi_pg_client::Config::from_uri(&url).expect("invalid database URL");
    let pg_conn = wasi_pg_client::Connection::connect(&config)
        .await
        .expect("failed to connect to test database");
    oidc_repository::connection::Connection::from_pg_client(pg_conn)
}

/// Clean all data tables (keep `_migrations`).
///
/// For HTTP tests using [`test_conn_no_tx`] this wraps a
/// `TRUNCATE ... CASCADE` in a transaction.  For DB tests using
/// [`test_conn`] (which already has an open transaction) this is a
/// no-op — the connection-drop rollback handles cleanup.
pub async fn clean_database(
    conn: &mut oidc_repository::connection::Connection,
) -> Result<(), oidc_core::OidcError> {
    // Serialize cleanup — only one test cleans at a time.
    // We use a std Mutex but NEVER hold it across .await.
    static CLEANUP_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

    // Acquire the lock briefly to serialize entry, then drop it.
    // The actual TRUNCATEs are still serialized because only one
    // caller passes the lock at a time.  We rely on single-threaded
    // execution (--test-threads=1) to avoid reordering issues.
    {
        let _guard = CLEANUP_MUTEX.lock().unwrap();
        // Lock held — serializes callers.  Dropped immediately below.
    }

    conn.begin()
        .await
        .map_err(|e| oidc_core::OidcError::Internal(e.to_string()))?;

    let tables = [
        "audit_events",
        "authorization_codes",
        "sessions",
        "api_keys",
        "signing_keys",
        "clients",
        "users",
        "realms",
    ];
    for table in &tables {
        if let Err(e) = conn
            .execute(&format!("TRUNCATE TABLE {} CASCADE", table))
            .await
        {
            let _ = conn.rollback().await;
            return Err(oidc_core::OidcError::Internal(e.to_string()));
        }
    }

    conn.commit()
        .await
        .map_err(|e| oidc_core::OidcError::Internal(e.to_string()))?;
    Ok(())
}

#[cfg(test)]
mod diag_tests {
    use super::*;

    /// Verify that V13 migration properly adds `deleted_at` columns
    /// to both `realms` and `clients` tables.
    #[tokio::test]
    async fn test_v13_migration_columns() {
        let url = database_url().await;
        let config = wasi_pg_client::Config::from_uri(&url).expect("invalid URL");
        let mut conn = wasi_pg_client::Connection::connect(&config)
            .await
            .expect("connect failed");

        // Check realms table columns
        let result = conn
            .query("SELECT column_name FROM information_schema.columns WHERE table_name = 'realms' ORDER BY ordinal_position")
            .await
            .expect("query failed");
        let columns: Vec<String> = result
            .into_rows()
            .iter()
            .filter_map(|r| r.get::<String>(0).ok())
            .collect();
        assert!(
            columns.contains(&"deleted_at".to_string()),
            "deleted_at column missing from realms table! Columns: {columns:?}"
        );

        // Check clients table columns
        let result = conn
            .query("SELECT column_name FROM information_schema.columns WHERE table_name = 'clients' ORDER BY ordinal_position")
            .await
            .expect("query failed");
        let columns: Vec<String> = result
            .into_rows()
            .iter()
            .filter_map(|r| r.get::<String>(0).ok())
            .collect();
        assert!(
            columns.contains(&"deleted_at".to_string()),
            "deleted_at column missing from clients table! Columns: {columns:?}"
        );

        // Gracefully close the connection.
        let _ = conn.close().await;
    }
}
