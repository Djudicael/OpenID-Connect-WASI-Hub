//! OIDC Dev Orchestrator — manages PostgreSQL container, migrations,
//! backend server, frontend dev server, and proxy for local development.
//!
//! Usage:
//!   cargo run -p oidc-dev -- start    # Start everything (DB + backend + frontend + proxy)
//!   cargo run -p oidc-dev -- stop     # Stop everything
//!   cargo run -p oidc-dev -- status   # Show status
//!   cargo run -p oidc-dev -- db-only  # Start DB + migrations only
//!   cargo run -p oidc-dev -- logs     # Tail all service logs
//!   cargo run -p oidc-dev -- wasm     # Start DB + WASM component via wasmtime
//!   cargo run -p oidc-dev -- test     # Run smoke tests against running server
//!
//! Dev Credentials (seeded on first start):
//!   Admin login:    admin@example.com / Admin123
//!   Client creds:   test-service / test-service-secret
//!
//! When the process exits (Ctrl-C), the PostgreSQL container is automatically dropped.

use std::path::Path;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use oidc_core::traits::Hasher;
use rustainers::ImageName;
use rustainers::runner::Runner;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

// ─── Configuration ──────────────────────────────────────────────────────────

const DB_IMAGE: &str = "docker.io/library/postgres";
const DB_TAG: &str = "16-alpine";
const DB_USER: &str = "postgres";
const DB_PASSWORD: &str = "postgres";
const DB_NAME: &str = "oidc_hub";

const BACKEND_BIN: &str = "openid-connect-wasi";
const FRONTEND_DIR: &str = "front/admin";
const MIGRATIONS_DIR: &str = "migrations/postgresql";

const BIND_ADDRESS: &str = "0.0.0.0";

// ─── State ──────────────────────────────────────────────────────────────────

#[derive(Debug)]
struct DevState {
    db_url: String,
    db_container: Option<rustainers::Container<rustainers::images::GenericImage>>,
    backend_port: u16,
    frontend_port: u16,
    proxy_port: u16,
    backend: Option<Child>,
    frontend: Option<Child>,
    proxy: Option<Child>,
}

impl DevState {
    fn new(db_url: String, backend_port: u16, frontend_port: u16, proxy_port: u16) -> Self {
        Self {
            db_url,
            db_container: None,
            backend_port,
            frontend_port,
            proxy_port,
            backend: None,
            frontend: None,
            proxy: None,
        }
    }
}

// ─── Main ───────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("info,oidc_dev=debug,rustainers=warn")
        .init();

    let cmd = std::env::args().nth(1).unwrap_or_else(|| "start".into());

    match cmd.as_str() {
        "start" => cmd_start().await,
        "stop" => cmd_stop().await,
        "status" => cmd_status().await,
        "db-only" => cmd_db_only().await,
        "logs" => cmd_logs().await,
        "wasm" => cmd_wasm().await,
        "test" => cmd_test().await,
        _ => {
            eprintln!("Usage: oidc-dev {{start|stop|status|db-only|logs|wasm|test}}");
            std::process::exit(1);
        }
    }
}

// ─── Start Command ──────────────────────────────────────────────────────────

async fn cmd_start() -> Result<()> {
    check_tools().await?;

    let state = Arc::new(Mutex::new(DevState::new(
        String::new(),
        pick_port(8080),
        pick_port(3008),
        pick_port(3000),
    )));

    let db_url = start_database(&state).await?;
    {
        let mut s = state.lock().await;
        s.db_url = db_url.clone();
    }

    let _proxy_port = {
        let s = state.lock().await;
        s.proxy_port
    };
    run_migrations(&db_url).await?;
    seed_data(&db_url, 3000).await?;
    build_frontend().await?;
    start_backend(&state, &db_url).await?;
    start_frontend_dev(&state).await?;
    start_proxy(&state).await?;

    let s = state.lock().await;
    let proxy_port = s.proxy_port;
    let backend_port = s.backend_port;
    let frontend_port = s.frontend_port;
    let wsl_ip = get_wsl_ip();
    info!("═══════════════════════════════════════════════════════════════");
    info!("  🚀 Dev environment ready!");
    info!("");
    info!("  Open your browser: http://localhost:{}", proxy_port);
    info!(
        "  (or from another machine: http://{}:{}",
        wsl_ip, proxy_port
    );
    info!("");
    info!("  Backend API:   http://localhost:{}", backend_port);
    info!("  Frontend dev:  http://localhost:{}", frontend_port);
    info!("  Database:      {}", s.db_url);
    info!("");
    info!("  Press Ctrl-C to stop everything (container auto-drops)");
    info!("═══════════════════════════════════════════════════════════════");
    drop(s);

    tokio::signal::ctrl_c().await?;
    info!("Shutting down...");
    shutdown_all(&state).await;

    Ok(())
}

// ─── DB-Only Command ────────────────────────────────────────────────────────

async fn cmd_db_only() -> Result<()> {
    check_tools().await?;

    let state = Arc::new(Mutex::new(DevState::new(String::new(), 0, 0, 0)));

    let db_url = start_database(&state).await?;
    run_migrations(&db_url).await?;
    seed_data(&db_url, 3000).await?;

    info!("═══════════════════════════════════════════════════════════════");
    info!("  Database ready: {}", db_url);
    info!("  Press Ctrl-C to stop (container auto-drops)");
    info!("═══════════════════════════════════════════════════════════════");

    tokio::signal::ctrl_c().await?;
    info!("Shutting down...");
    shutdown_all(&state).await;

    Ok(())
}

// ─── Stop Command ───────────────────────────────────────────────────────────

async fn cmd_stop() -> Result<()> {
    kill_process_by_name("openid-connect-wasi").await;
    kill_process_by_name(r"node.*dev\.js").await;
    kill_process_by_name("node.*proxy").await;

    let _ = Command::new("podman")
        .args(["rm", "-f", "oidc-hub-postgres"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await;

    let proxy_path = std::env::temp_dir().join("oidc-hub-proxy.js");
    let _ = tokio::fs::remove_file(&proxy_path).await;

    info!("All services stopped.");
    Ok(())
}

// ─── Status Command ─────────────────────────────────────────────────────────

async fn cmd_status() -> Result<()> {
    let backend_port = std::env::var("OIDC_SERVER_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8080);
    let frontend_port = std::env::var("OIDC_FRONTEND_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3008);
    let proxy_port = std::env::var("OIDC_PROXY_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3000);

    let backend_running = is_port_open(backend_port).await;
    let frontend_running = is_port_open(frontend_port).await;
    let proxy_running = is_port_open(proxy_port).await;

    println!("=== OIDC Hub Dev Environment Status ===");
    println!();
    println!(
        "Backend (port {}):    {}",
        backend_port,
        if backend_running {
            "✅ Running"
        } else {
            "❌ Not running"
        }
    );
    println!(
        "Frontend (port {}):   {}",
        frontend_port,
        if frontend_running {
            "✅ Running"
        } else {
            "❌ Not running"
        }
    );
    println!(
        "Proxy (port {}):      {}",
        proxy_port,
        if proxy_running {
            "✅ Running"
        } else {
            "❌ Not running"
        }
    );
    println!();

    Ok(())
}

// ─── Logs Command ───────────────────────────────────────────────────────────

async fn cmd_logs() -> Result<()> {
    let log_dir = std::env::temp_dir().join("oidc-hub-logs");
    if !log_dir.exists() {
        println!("No log directory found at {}", log_dir.display());
        return Ok(());
    }

    let mut entries: Vec<_> = std::fs::read_dir(&log_dir)?
        .filter_map(|e| e.ok())
        .collect();
    entries.sort_by_key(|e| e.file_name());

    for entry in entries {
        let path = entry.path();
        let name = path.file_stem().unwrap_or_default().to_string_lossy();
        println!("\n--- {} ---", name);
        if let Ok(content) = tokio::fs::read_to_string(&path).await {
            print!("{}", content);
        }
    }

    Ok(())
}

// ─── WASM Command ──────────────────────────────────────────────────────────────

async fn cmd_wasm() -> Result<()> {
    check_tools().await?;

    let state = Arc::new(Mutex::new(DevState::new(
        String::new(),
        pick_port(8080),
        0, // no frontend
        0, // no proxy
    )));

    let db_url = start_database(&state).await?;
    {
        let mut s = state.lock().await;
        s.db_url = db_url.clone();
    }

    run_migrations(&db_url).await?;
    seed_data(&db_url, 8080).await?;

    // Build WASM component
    info!("Building WASM component...");
    let build = Command::new("cargo")
        .args([
            "build",
            "-p",
            "openid-connect-wasi",
            "--target",
            "wasm32-wasip2",
            "--release",
        ])
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .context("failed to build WASM component")?;

    let output = build.wait_with_output().await?;
    if !output.status.success() {
        anyhow::bail!("WASM build failed (exit code: {:?})", output.status.code());
    }
    info!("WASM component built.");

    // Check wasmtime is available
    let wasmtime_check = Command::new("wasmtime")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await;
    if wasmtime_check.is_err() || !wasmtime_check.unwrap().success() {
        anyhow::bail!(
            "wasmtime is required but not found. Install it first:\n  curl https://wasmtime.dev/install.sh -sSf | bash"
        );
    }

    let port = {
        let s = state.lock().await;
        s.backend_port
    };

    let encryption_key =
        "2a3131371e4b5559606b70777e858f969da4acb3babec5ccc3cdd5dddbe3e9f0".to_string();

    let wasm_path = "target/wasm32-wasip2/release/openid_connect_wasi.wasm";
    info!("Starting WASM component via wasmtime on port {port}...");

    let mut cmd = Command::new("wasmtime");
    cmd.arg("run")
        .arg("--wasi")
        .arg("inherit-network")
        .arg("--wasi")
        .arg("inherit-env")
        .arg("--env")
        .arg(format!("OIDC_DATABASE_URL={}", &db_url))
        .arg("--env")
        .arg(format!("OIDC_SERVER_PORT={}", port))
        .arg("--env")
        .arg(format!("OIDC_SERVER_BIND_ADDRESS={}", BIND_ADDRESS))
        .arg("--env")
        .arg(format!("OIDC_ENCRYPTION_KEY={}", &encryption_key))
        .arg("--env")
        .arg(format!("OIDC_ISSUER=http://localhost:{}", port))
        .arg("--env")
        .arg("OIDC_RATE_LIMIT_MAX=1000")
        .arg("--env")
        .arg("OIDC_RATE_LIMIT_WINDOW_SECS=60")
        .arg(wasm_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn().context("failed to start wasmtime")?;

    let stderr = child.stderr.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    tokio::spawn(stream_logs("wasm", stderr));
    tokio::spawn(stream_logs("wasm-out", stdout));

    let health_url = format!("http://127.0.0.1:{port}/health");
    wait_for_http(&health_url, 30).await?;

    {
        let mut s = state.lock().await;
        s.backend = Some(child);
    }

    info!("═══════════════════════════════════════════════════════════════");
    info!("  WASM dev environment ready!");
    info!("");
    info!("  Backend API:   http://localhost:{}", port);
    info!("  Database:      {}", db_url);
    info!("");
    info!("  Press Ctrl-C to stop (container auto-drops)");
    info!("═══════════════════════════════════════════════════════════════");

    tokio::signal::ctrl_c().await?;
    info!("Shutting down...");
    shutdown_all(&state).await;

    Ok(())
}

// ─── Test Command ────────────────────────────────────────────────────────────

async fn cmd_test() -> Result<()> {
    // Quick smoke test against a running dev environment
    let port: u16 = std::env::var("OIDC_SERVER_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8080);
    let base_url = format!("http://localhost:{}", port);

    info!("Running smoke tests against {}...", base_url);

    let client = reqwest::Client::new();
    let mut passed = 0u32;
    let mut failed = 0u32;

    // Test 1: Health endpoint
    match client.get(format!("{base_url}/health")).send().await {
        Ok(resp) if resp.status().is_success() => {
            info!("  ✓ GET /health → {}", resp.status());
            passed += 1;
        }
        Ok(resp) => {
            warn!("  ✗ GET /health → {} (expected 200)", resp.status());
            failed += 1;
        }
        Err(e) => {
            warn!("  ✗ GET /health → connection failed: {}", e);
            failed += 1;
        }
    }

    // Test 2: Health ready (checks DB)
    match client.get(format!("{base_url}/health/ready")).send().await {
        Ok(resp) if resp.status().is_success() => {
            info!("  ✓ GET /health/ready → {}", resp.status());
            passed += 1;
        }
        Ok(resp) => {
            warn!("  ✗ GET /health/ready → {} (expected 200)", resp.status());
            failed += 1;
        }
        Err(e) => {
            warn!("  ✗ GET /health/ready → connection failed: {}", e);
            failed += 1;
        }
    }

    // Test 3: Discovery document
    match client
        .get(format!("{base_url}/.well-known/openid-configuration"))
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            let body: serde_json::Value = resp.json().await.unwrap_or_default();
            let has_issuer = body.get("issuer").is_some();
            let has_algs = body.get("id_token_signing_alg_values_supported").is_some();
            if has_issuer && has_algs {
                info!("  ✓ GET /.well-known/openid-configuration → valid");
                passed += 1;
            } else {
                warn!("  ✗ GET /.well-known/openid-configuration → missing fields");
                failed += 1;
            }
        }
        Ok(resp) => {
            warn!(
                "  ✗ GET /.well-known/openid-configuration → {}",
                resp.status()
            );
            failed += 1;
        }
        Err(e) => {
            warn!("  ✗ GET /.well-known/openid-configuration → {}", e);
            failed += 1;
        }
    }

    // Test 4: JWKS endpoint
    match client.get(format!("{base_url}/oidc/jwks")).send().await {
        Ok(resp) if resp.status().is_success() => {
            let body: serde_json::Value = resp.json().await.unwrap_or_default();
            let keys = body.get("keys").and_then(|k| k.as_array());
            if let Some(keys) = keys {
                let has_rsa = keys
                    .iter()
                    .any(|k| k.get("kty").map(|v| v == "RSA").unwrap_or(false));
                let has_okp = keys
                    .iter()
                    .any(|k| k.get("kty").map(|v| v == "OKP").unwrap_or(false));
                info!(
                    "  ✓ GET /oidc/jwks → {} keys (RSA: {}, EdDSA: {})",
                    keys.len(),
                    has_rsa,
                    has_okp
                );
                passed += 1;
            } else {
                warn!("  ✗ GET /oidc/jwks → no keys array");
                failed += 1;
            }
        }
        Ok(resp) => {
            warn!("  ✗ GET /oidc/jwks → {}", resp.status());
            failed += 1;
        }
        Err(e) => {
            warn!("  ✗ GET /oidc/jwks → {}", e);
            failed += 1;
        }
    }

    // Test 5: Client credentials token
    match client
        .post(format!("{base_url}/oidc/token"))
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", "test-service"),
            ("client_secret", "test-service-secret"),
        ])
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            let body: serde_json::Value = resp.json().await.unwrap_or_default();
            let has_token = body.get("access_token").is_some();
            if has_token {
                info!("  ✓ POST /oidc/token (client_credentials) → access_token issued");
                passed += 1;
            } else {
                warn!("  ✗ POST /oidc/token (client_credentials) → no access_token");
                failed += 1;
            }
        }
        Ok(resp) => {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            warn!(
                "  ✗ POST /oidc/token (client_credentials) → {} : {}",
                status, body
            );
            failed += 1;
        }
        Err(e) => {
            warn!("  ✗ POST /oidc/token (client_credentials) → {}", e);
            failed += 1;
        }
    }

    // Test 6: Login with admin credentials
    match client
        .post(format!("{base_url}/oidc/login"))
        .json(&serde_json::json!({
            "email": "admin@example.com",
            "password": "Admin123",
            "client_id": "admin-ui"
        }))
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            let body: serde_json::Value = resp.json().await.unwrap_or_default();
            let has_tokens = body.get("access_token").is_some() && body.get("id_token").is_some();
            if has_tokens {
                info!("  ✓ POST /oidc/login → tokens issued");
                passed += 1;
            } else {
                warn!("  ✗ POST /oidc/login → missing tokens");
                failed += 1;
            }
        }
        Ok(resp) => {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            warn!("  ✗ POST /oidc/login → {} : {}", status, body);
            failed += 1;
        }
        Err(e) => {
            warn!("  ✗ POST /oidc/login → {}", e);
            failed += 1;
        }
    }

    info!("");
    info!("═══════════════════════════════════════════════════════════════");
    info!("  Smoke test results: {} passed, {} failed", passed, failed);
    if failed == 0 {
        info!("  All tests passed! ✓");
    } else {
        warn!("  Some tests failed. Is the server running? Try: cargo run -p oidc-dev -- start");
    }
    info!("═══════════════════════════════════════════════════════════════");

    if failed > 0 {
        std::process::exit(1);
    }
    Ok(())
}

// ─── Tool Checks ────────────────────────────────────────────────────────────

async fn check_tools() -> Result<()> {
    let podman_check = Command::new("podman")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await;
    if podman_check.is_err() || !podman_check.unwrap().success() {
        anyhow::bail!(
            "podman is required but not found. Install it first:\n  sudo apt-get install -y podman"
        );
    }

    let node_check = Command::new("node")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await;
    if node_check.is_err() || !node_check.unwrap().success() {
        anyhow::bail!("Node.js is required but not found.");
    }

    let npm_check = Command::new("npm")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await;
    if npm_check.is_err() || !npm_check.unwrap().success() {
        anyhow::bail!("npm is required but not found.");
    }

    Ok(())
}

// ─── Database ───────────────────────────────────────────────────────────────

async fn start_database(state: &Arc<Mutex<DevState>>) -> Result<String> {
    info!("Starting PostgreSQL container via rustainers...");

    let runner = Runner::podman().context("Failed to create Podman runner")?;

    let image_name = ImageName::new_with_tag(DB_IMAGE, DB_TAG);
    let mut image = rustainers::images::GenericImage::new(image_name);
    image.add_env_var("POSTGRES_DB", DB_NAME);
    image.add_env_var("POSTGRES_USER", DB_USER);
    image.add_env_var("POSTGRES_PASSWORD", DB_PASSWORD);
    image.add_port_mapping(5432);
    image.set_container_name("oidc-hub-postgres");

    let container = runner
        .start(image)
        .await
        .context("Failed to start PostgreSQL container")?;

    let host_port = container
        .host_port(5432)
        .await
        .context("Failed to get host port from container")?;

    let db_url = format!("postgresql://{DB_USER}:{DB_PASSWORD}@localhost:{host_port}/{DB_NAME}");

    info!("Container started on host port {host_port}, waiting for PostgreSQL...");

    wait_for_postgres(&db_url).await?;

    {
        let mut s = state.lock().await;
        s.db_container = Some(container);
    }

    info!("PostgreSQL is ready: {}", db_url);
    Ok(db_url)
}

async fn wait_for_postgres(url: &str) -> Result<()> {
    let config = wasi_pg_client::Config::from_uri(url).context("invalid database URL")?;
    let start = std::time::Instant::now();
    let timeout = Duration::from_secs(60);

    loop {
        if start.elapsed() > timeout {
            anyhow::bail!("PostgreSQL did not become ready within 60s");
        }

        match wasi_pg_client::Connection::connect(&config).await {
            Ok(mut conn) => match conn.query("SELECT 1").await {
                Ok(_) => return Ok(()),
                Err(e) => {
                    debug!("query failed: {e}, retrying...");
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            },
            Err(e) => {
                debug!("connect failed: {e}, retrying...");
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
    }
}

// ─── Migrations ─────────────────────────────────────────────────────────────

async fn run_migrations(db_url: &str) -> Result<()> {
    info!("Running database migrations...");

    let config = wasi_pg_client::Config::from_uri(db_url).context("invalid database URL")?;
    let mut conn = wasi_pg_client::Connection::connect(&config)
        .await
        .context("failed to connect to database for migrations")?;

    let migrations_dir = Path::new(MIGRATIONS_DIR);
    if !migrations_dir.exists() {
        anyhow::bail!(
            "migrations directory not found: {}",
            migrations_dir.display()
        );
    }

    conn.query(
        r#"
        CREATE TABLE IF NOT EXISTS _migrations (
            id SERIAL PRIMARY KEY,
            filename TEXT NOT NULL UNIQUE,
            applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    "#,
    )
    .await
    .context("failed to create _migrations table")?;

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
            debug!("skip {filename} (already applied)");
            continue;
        }

        let path = entry.path();
        let sql = std::fs::read_to_string(&path)?;

        info!("apply {filename}");
        conn.query(&sql)
            .await
            .with_context(|| format!("failed to apply {filename}"))?;

        conn.execute_params(
            "INSERT INTO _migrations (filename) VALUES ($1)",
            &[&filename],
        )
        .await?;

        info!("applied {filename} ok");
    }

    info!("Migrations complete.");
    Ok(())
}

// ─── Seed Data ──────────────────────────────────────────────────────────────

async fn seed_data(db_url: &str, proxy_port: u16) -> Result<()> {
    info!("Seeding dev data...");

    let config = wasi_pg_client::Config::from_uri(db_url).context("invalid database URL")?;
    let hasher = oidc_core::traits::hasher::Argon2idHasher::new();

    // 1. Realm
    info!("Step 1/5: realm...");
    let realm_id = {
        let pg_conn = wasi_pg_client::Connection::connect(&config)
            .await
            .context("seed: connect for realm")?;
        let mut conn = oidc_repository::Connection::from_pg_client(pg_conn);
        let repo = oidc_repository::repositories::realm_repo::RealmRepo;
        match repo.find_by_name(&mut conn, "master").await {
            Ok(Some(realm)) => realm.id,
            Ok(None) => {
                let id = oidc_core::utils::generate_uuid_v7();
                let realm = oidc_core::models::Realm {
                    id,
                    name: "master".into(),
                    display_name: "Master Realm".into(),
                    enabled: true,
                    config: serde_json::Value::Object(serde_json::Map::new()),
                    deleted_at: None,
                };
                repo.create(&mut conn, &realm)
                    .await
                    .map_err(|e| anyhow::anyhow!("realm create: {e}"))?;
                info!("Created 'master' realm");
                id
            }
            Err(e) => return Err(anyhow::anyhow!("realm lookup: {e}")),
        }
    };

    // 2. Admin user
    info!("Step 2/5: admin user...");
    let user_id = {
        let pg_conn = wasi_pg_client::Connection::connect(&config)
            .await
            .context("seed: connect for user")?;
        let mut conn = oidc_repository::Connection::from_pg_client(pg_conn);
        let repo = oidc_repository::repositories::user_repo::UserRepo;
        match repo
            .find_by_email(&mut conn, realm_id, "admin@example.com")
            .await
        {
            Ok(Some(user)) => user.id,
            Ok(None) => {
                let id = oidc_core::utils::generate_uuid_v7();
                let password_hash = hasher
                    .hash("Admin123")
                    .map_err(|e| anyhow::anyhow!("hash failed: {e}"))?;
                let user = oidc_core::models::User {
                    id,
                    realm_id,
                    email: "admin@example.com".into(),
                    email_verified: true,
                    username: Some("admin".into()),
                    password_hash: Some(password_hash),
                    given_name: Some("Admin".into()),
                    family_name: Some("User".into()),
                    middle_name: None,
                    nickname: None,
                    preferred_username: None,
                    profile: None,
                    picture: None,
                    website: None,
                    gender: None,
                    birthdate: None,
                    zoneinfo: None,
                    phone_number: None,
                    phone_number_verified: None,
                    locale: "en".into(),
                    attributes: serde_json::Value::Object(serde_json::Map::new()),
                    enabled: true,
                    deleted_at: None,
                    updated_at: chrono::Utc::now(),
                };
                repo.create(&mut conn, &user)
                    .await
                    .map_err(|e| anyhow::anyhow!("user create: {e}"))?;
                info!("Created admin user (admin@example.com / Admin123)");
                id
            }
            Err(e) => return Err(anyhow::anyhow!("user lookup: {e}")),
        }
    };

    // 3. Clients
    info!("Step 3/5: OIDC clients...");
    {
        let pg_conn = wasi_pg_client::Connection::connect(&config)
            .await
            .context("seed: connect for client")?;
        let mut conn = oidc_repository::Connection::from_pg_client(pg_conn);
        let repo = oidc_repository::repositories::client_repo::ClientRepo;

        // Public client (admin-ui)
        if repo
            .find_by_client_id(&mut conn, "admin-ui")
            .await?
            .is_none()
        {
            let id = oidc_core::utils::generate_uuid_v7();
            let client = oidc_core::models::Client {
                id,
                realm_id,
                client_id: "admin-ui".into(),
                client_type: oidc_core::models::ClientType::Public,
                client_secret_hash: None,
                name: "Admin UI".into(),
                redirect_uris: vec![
                    format!("http://localhost:{}/callback", proxy_port),
                    format!("http://localhost:{}/admin/callback", proxy_port),
                ],
                allowed_scopes: vec!["openid".into(), "profile".into(), "email".into()],
                allowed_grant_types: vec!["authorization_code".into(), "refresh_token".into()],
                pkce_required: true,
                enabled: true,
                deleted_at: None,
                token_endpoint_auth_method: "none".into(),
                jwks_uri: None,
                jwks: None,
                request_uris: vec![],
                client_secret_encrypted: None,
                frontchannel_logout_uri: None,
                frontchannel_logout_session_required: false,
                backchannel_logout_uri: None,
                backchannel_logout_session_required: false,
                post_logout_redirect_uris: vec![],
                subject_type: "public".into(),
                sector_identifier_uri: None,
                response_modes: vec!["query".to_string(), "fragment".to_string()],
                id_token_encrypted_response_alg: None,
                id_token_encrypted_response_enc: None,
                id_token_encryption_key_encrypted: None,
                id_token_encryption_key_pem: None,
            };
            repo.create(&mut conn, &client)
                .await
                .map_err(|e| anyhow::anyhow!("client create: {e}"))?;
            info!("Created 'admin-ui' public OIDC client");
        }

        // Confidential client (for client_credentials flow / load testing)
        if repo
            .find_by_client_id(&mut conn, "test-service")
            .await?
            .is_none()
        {
            let id = oidc_core::utils::generate_uuid_v7();
            let client_secret_hash = hasher
                .hash("test-service-secret")
                .map_err(|e| anyhow::anyhow!("hash failed: {e}"))?;
            let client = oidc_core::models::Client {
                id,
                realm_id,
                client_id: "test-service".into(),
                client_type: oidc_core::models::ClientType::Confidential,
                client_secret_hash: Some(client_secret_hash),
                name: "Test Service (client_credentials)".into(),
                redirect_uris: vec![],
                allowed_scopes: vec!["openid".into(), "profile".into(), "email".into()],
                allowed_grant_types: vec!["client_credentials".into()],
                pkce_required: false,
                enabled: true,
                deleted_at: None,
                token_endpoint_auth_method: "client_secret_basic".into(),
                jwks_uri: None,
                jwks: None,
                request_uris: vec![],
                client_secret_encrypted: None,
                frontchannel_logout_uri: None,
                frontchannel_logout_session_required: false,
                backchannel_logout_uri: None,
                backchannel_logout_session_required: false,
                post_logout_redirect_uris: vec![],
                subject_type: "public".into(),
                sector_identifier_uri: None,
                response_modes: vec!["query".to_string(), "fragment".to_string()],
                id_token_encrypted_response_alg: None,
                id_token_encrypted_response_enc: None,
                id_token_encryption_key_encrypted: None,
                id_token_encryption_key_pem: None,
            };
            repo.create(&mut conn, &client)
                .await
                .map_err(|e| anyhow::anyhow!("client create: {e}"))?;
            info!(
                "Created 'test-service' confidential client (client_id: test-service, client_secret: test-service-secret)"
            );
        }
    }

    // 4. API key — best effort, don't let it hang the whole startup
    info!("Step 4/5: admin API key...");
    let api_key_result = tokio::time::timeout(Duration::from_secs(10), async {
        let pg_conn = wasi_pg_client::Connection::connect(&config)
            .await
            .context("seed: connect for api key")?;
        let mut conn = oidc_repository::Connection::from_pg_client(pg_conn);

        // Check if any active API key already exists
        let repo = oidc_repository::repositories::api_key_repo::ApiKeyRepo;
        let existing = repo
            .find_by_realm(&mut conn, realm_id, false)
            .await
            .map_err(|e| anyhow::anyhow!("api key lookup: {e}"))?;
        if !existing.is_empty() {
            info!("Admin API key already exists.");
            return Ok::<_, anyhow::Error>(());
        }

        // Use ApiKeyService::generate_key for proper key generation
        let (_api_key, raw_key) = oidc_apikey::ApiKeyService::generate_key(
            &mut conn,
            realm_id,
            "Dev Admin Key".into(),
            vec!["admin".into()],
            None, // no expiration
            Some(user_id),
        )
        .await
        .map_err(|e| anyhow::anyhow!("api key generate: {e}"))?;

        info!("═══════════════════════════════════════════════════════════════");
        info!("  ADMIN API KEY (save this — shown only once):");
        info!("  {}", raw_key);
        info!("═══════════════════════════════════════════════════════════════");
        Ok::<_, anyhow::Error>(())
    })
    .await;

    match api_key_result {
        Ok(Ok(())) => {}
        Ok(Err(e)) => warn!("API key seed failed (non-fatal): {e}"),
        Err(_) => warn!("API key seed timed out (non-fatal), continuing..."),
    }

    // 5. Print dev credentials summary
    info!("Step 5/5: dev credentials summary...");
    info!("═══════════════════════════════════════════════════════════════");
    info!("  Dev Credentials:");
    info!("");
    info!("  Admin login:");
    info!("    Email:    admin@example.com");
    info!("    Password: Admin123");
    info!("");
    info!("  Confidential client (client_credentials):");
    info!("    Client ID:     test-service");
    info!("    Client Secret: test-service-secret");
    info!("");
    info!("  Note: JWT signing keys are auto-generated on startup.");
    info!("  Tokens are invalidated on server restart.");
    info!("═══════════════════════════════════════════════════════════════");

    info!("Seed data complete.");
    Ok(())
}

// ─── Frontend Build ─────────────────────────────────────────────────────────

async fn build_frontend() -> Result<()> {
    info!("Building frontend...");

    let frontend_dir = Path::new(FRONTEND_DIR);
    if !frontend_dir.exists() {
        anyhow::bail!("frontend directory not found: {}", frontend_dir.display());
    }

    info!("Running npm install (this may take a while on first run)...");
    let npm_install = Command::new("npm")
        .arg("install")
        .current_dir(frontend_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("failed to run npm install")?;

    let output = npm_install.wait_with_output().await?;
    if !output.status.success() {
        anyhow::bail!("npm install failed (exit code: {:?})", output.status.code());
    }
    info!("npm install complete.");

    info!("Running node buildJs.js...");
    let build = Command::new("node")
        .arg("buildJs.js")
        .current_dir(frontend_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("failed to run node buildJs.js")?;

    let output = build.wait_with_output().await?;
    if !output.status.success() {
        anyhow::bail!(
            "frontend build failed (exit code: {:?})",
            output.status.code()
        );
    }
    info!("node buildJs.js complete.");

    info!("Frontend built.");
    Ok(())
}

async fn start_backend(state: &Arc<Mutex<DevState>>, db_url: &str) -> Result<()> {
    let port = {
        let s = state.lock().await;
        s.backend_port
    };
    let proxy_port = {
        let s = state.lock().await;
        s.proxy_port
    };

    info!("Building backend (this may take a while on first run)...");
    let build = Command::new("cargo")
        .args(["build", "-p", BACKEND_BIN, "--release", "--quiet"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("failed to build backend")?;

    let output = build.wait_with_output().await?;
    if !output.status.success() {
        anyhow::bail!(
            "backend build failed (exit code: {:?})",
            output.status.code()
        );
    }
    info!("Backend built.");

    info!("Starting backend server on port {port}...");

    // Generate a deterministic 32-byte hex encryption key for dev
    // Not for production — fixed seed, just for local development
    let encryption_key =
        "2a3131371e4b5559606b70777e858f969da4acb3babec5ccc3cdd5dddbe3e9f0".to_string();

    // Note: OIDC_SIGNING_KEY and OIDC_ED25519_KEY are NOT set here.
    // The backend auto-generates RSA + Ed25519 keypairs on startup.
    // This means JWTs are invalidated on restart — acceptable for dev.
    // To persist keys across restarts, generate PEM files and set the env vars.

    let mut cmd = Command::new("cargo");
    cmd.arg("run")
        .arg("-p")
        .arg(BACKEND_BIN)
        .arg("--release")
        .arg("--quiet")
        .env("OIDC_DATABASE_URL", db_url)
        .env("OIDC_SERVER_PORT", port.to_string())
        .env("OIDC_ISSUER", format!("http://localhost:{proxy_port}"))
        .env("OIDC_SERVER_BIND_ADDRESS", BIND_ADDRESS)
        .env("OIDC_ENCRYPTION_KEY", &encryption_key)
        .env(
            "OIDC_CORS_ORIGINS",
            format!("http://localhost:{proxy_port}"),
        )
        .env("OIDC_RATE_LIMIT_MAX", "1000") // High limit for dev/testing
        .env("OIDC_RATE_LIMIT_WINDOW_SECS", "60")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn().context("failed to start backend")?;

    let stderr = child.stderr.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    tokio::spawn(stream_logs("backend", stderr));
    tokio::spawn(stream_logs("backend-out", stdout));

    let health_url = format!("http://127.0.0.1:{port}/health");
    wait_for_http(&health_url, 30).await?;

    {
        let mut s = state.lock().await;
        s.backend = Some(child);
    }

    info!("Backend server ready at http://localhost:{port}");
    Ok(())
}

// ─── Frontend Dev Server ────────────────────────────────────────────────────

async fn start_frontend_dev(state: &Arc<Mutex<DevState>>) -> Result<()> {
    let port = {
        let s = state.lock().await;
        s.frontend_port
    };

    info!("Starting frontend dev server on port {port}...");

    let frontend_dir = Path::new(FRONTEND_DIR);

    let mut cmd = Command::new("node");
    cmd.arg("dev.js")
        .env("PORT", port.to_string())
        .env("BIND_ADDRESS", BIND_ADDRESS)
        .current_dir(frontend_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn().context("failed to start frontend dev server")?;

    let stderr = child.stderr.take().unwrap();
    tokio::spawn(stream_logs("frontend", stderr));

    let url = format!("http://127.0.0.1:{port}");
    wait_for_http(&url, 15).await?;

    {
        let mut s = state.lock().await;
        s.frontend = Some(child);
    }

    info!("Frontend dev server ready at http://localhost:{port}");
    Ok(())
}

// ─── Proxy ────────────────────────────────────────────────────────────────────

async fn start_proxy(state: &Arc<Mutex<DevState>>) -> Result<()> {
    let (backend_port, frontend_port, proxy_port) = {
        let s = state.lock().await;
        (s.backend_port, s.frontend_port, s.proxy_port)
    };

    info!("Starting proxy on port {proxy_port}...");

    let proxy_modules_dir = std::env::temp_dir().join("oidc-hub-proxy-modules");
    if !proxy_modules_dir.join("node_modules/http-proxy").exists() {
        info!("Installing http-proxy into temp directory...");
        let npm_install = Command::new("npm")
            .args([
                "install",
                "--prefix",
                &proxy_modules_dir.to_string_lossy(),
                "http-proxy",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("failed to run npm install http-proxy")?;

        let output = npm_install.wait_with_output().await?;
        if !output.status.success() {
            warn!(
                "npm install http-proxy failed (exit code: {:?})",
                output.status.code()
            );
        }
    }

    let proxy_script = format!(
        r#"
const path = require('path');
const nodePaths = (process.env.NODE_PATH || '').split(path.delimiter).filter(Boolean);
nodePaths.forEach(p => {{ if (!module.paths.includes(p)) module.paths.unshift(p); }});

const http = require('http');
const httpProxy = require('http-proxy');

const proxy = httpProxy.createProxyServer({{}});
const PROXY_PORT = {proxy_port};
const BACKEND_PORT = {backend_port};
const FRONTEND_PORT = {frontend_port};
const BIND_ADDRESS = '{bind}';

const server = http.createServer((req, res) => {{
    if (req.method === 'OPTIONS') {{
        res.setHeader('Access-Control-Allow-Origin', '*');
        res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-API-Key, X-CSRF-Token');
        res.setHeader('Access-Control-Max-Age', '86400');
        res.writeHead(200);
        res.end();
        return;
    }}

    const isApi = req.url.startsWith('/api/') || req.url.startsWith('/oidc/') || req.url.startsWith('/.well-known/') || req.url.startsWith('/health') || req.url.startsWith('/admin') || req.url.startsWith('/realms/');
    const target = isApi ? `http://127.0.0.1:${{BACKEND_PORT}}` : `http://127.0.0.1:${{FRONTEND_PORT}}`;
    console.log(`[proxy] ${{req.method}} ${{req.url}} -> ${{isApi ? 'BACKEND' : 'FRONTEND'}} (${{target}})`);

    proxy.web(req, res, {{ target }}, (err) => {{
        console.error('Proxy error:', err.message);
        if (!res.headersSent) {{
            res.writeHead(502);
            res.end('Bad Gateway');
        }}
    }});
}});

// Add CORS headers to every proxied response (before headers are sent to client)
proxy.on('proxyRes', (proxyRes, req, res) => {{
    proxyRes.headers['access-control-allow-origin'] = '*';
    proxyRes.headers['access-control-allow-methods'] = 'GET, POST, PUT, DELETE, OPTIONS';
    proxyRes.headers['access-control-allow-headers'] = 'Content-Type, Authorization, X-API-Key, X-CSRF-Token';
}});

server.on('upgrade', (req, socket, head) => {{
    proxy.ws(req, socket, head, {{ target: `http://127.0.0.1:${{FRONTEND_PORT}}` }});
}});

proxy.on('error', (err, req, res) => {{
    if (res && !res.headersSent) {{
        res.writeHead(502);
        res.end('Bad Gateway');
    }}
}});

server.listen(PROXY_PORT, BIND_ADDRESS, () => {{
    console.log(`Proxy running at http://${{BIND_ADDRESS}}:${{PROXY_PORT}}`);
}});
"#,
        bind = BIND_ADDRESS
    );

    let proxy_path = std::env::temp_dir().join("oidc-hub-proxy.js");
    tokio::fs::write(&proxy_path, proxy_script)
        .await
        .context("failed to write proxy script")?;

    let mut cmd = Command::new("node");
    cmd.arg(&proxy_path)
        .env(
            "NODE_PATH",
            proxy_modules_dir
                .join("node_modules")
                .to_string_lossy()
                .to_string(),
        )
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn().context("failed to start proxy")?;

    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    tokio::spawn(stream_logs("proxy", stderr));
    tokio::spawn(stream_logs("proxy-out", stdout));

    let url = format!("http://127.0.0.1:{proxy_port}");
    wait_for_http(&url, 10).await?;

    {
        let mut s = state.lock().await;
        s.proxy = Some(child);
    }

    info!("Proxy ready at http://localhost:{proxy_port}");
    Ok(())
}

// ─── Shutdown ─────────────────────────────────────────────────────────────────

async fn shutdown_all(state: &Arc<Mutex<DevState>>) {
    let mut s = state.lock().await;

    if let Some(mut proxy) = s.proxy.take() {
        info!("Stopping proxy...");
        let _ = proxy.kill().await;
    }

    if let Some(mut frontend) = s.frontend.take() {
        info!("Stopping frontend dev server...");
        let _ = frontend.kill().await;
    }

    if let Some(mut backend) = s.backend.take() {
        info!("Stopping backend server...");
        let _ = backend.kill().await;
    }

    if s.db_container.take().is_some() {
        info!("PostgreSQL container dropped.");
    }

    let proxy_path = std::env::temp_dir().join("oidc-hub-proxy.js");
    let _ = tokio::fs::remove_file(&proxy_path).await;

    info!("Shutdown complete.");
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn pick_port(start: u16) -> u16 {
    portpicker::pick_unused_port().unwrap_or(start)
}

async fn wait_for_http(url: &str, timeout_secs: u64) -> Result<()> {
    let client = reqwest::Client::new();
    let start = std::time::Instant::now();

    loop {
        if start.elapsed().as_secs() > timeout_secs {
            anyhow::bail!("HTTP endpoint {url} did not become ready within {timeout_secs}s");
        }

        match client.get(url).send().await {
            Ok(_) => return Ok(()),
            Err(e) => {
                debug!("HTTP check failed: {e}, retrying...");
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
    }
}

async fn stream_logs(name: &str, output: impl tokio::io::AsyncRead + Unpin) {
    let reader = BufReader::new(output);
    let mut lines = reader.lines();

    while let Ok(Some(line)) = lines.next_line().await {
        info!("[{name}] {line}");
    }
}

async fn is_port_open(port: u16) -> bool {
    tokio::net::TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .is_ok()
}

async fn kill_process_by_name(pattern: &str) {
    let _ = Command::new("pkill")
        .args(["-f", pattern])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await;
}

fn get_wsl_ip() -> String {
    std::env::var("WSL_IP")
        .ok()
        .or_else(|| {
            std::fs::read_to_string("/etc/resolv.conf")
                .ok()
                .and_then(|content| {
                    content
                        .lines()
                        .find(|l| l.starts_with("nameserver"))
                        .and_then(|l| l.split_whitespace().nth(1).map(String::from))
                })
        })
        .unwrap_or_else(|| "127.0.0.1".into())
}
