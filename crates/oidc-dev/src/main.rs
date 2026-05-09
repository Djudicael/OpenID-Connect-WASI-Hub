//! OIDC Dev Orchestrator — manages PostgreSQL container, migrations,
//! backend server, frontend dev server, and proxy for local development.
//!
//! Usage:
//!   cargo run -p oidc-dev -- start    # Start everything
//!   cargo run -p oidc-dev -- stop     # Stop everything
//!   cargo run -p oidc-dev -- status   # Show status
//!   cargo run -p oidc-dev -- db-only  # Start DB + migrations only
//!   cargo run -p oidc-dev -- logs     # Tail all service logs
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
        _ => {
            eprintln!("Usage: oidc-dev {{start|stop|status|db-only|logs}}");
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

    // 1. Realm
    info!("Step 1/4: realm...");
    let realm_id = {
        let mut conn = wasi_pg_client::Connection::connect(&config)
            .await
            .context("seed: connect for realm")?;
        let check = conn
            .query_params("SELECT id FROM realms WHERE name = $1", &[&"master"])
            .await?;
        let rows = check.into_rows();
        if rows.is_empty() {
            let id = oidc_core::utils::generate_uuid_v7();
            conn.execute_params(
                "INSERT INTO realms (id, name, display_name, enabled) VALUES ($1, $2, $3, $4)",
                &[&id, &"master", &"Master Realm", &true],
            )
            .await?;
            info!("Created 'master' realm");
            id
        } else {
            let row = rows.into_iter().next().unwrap();
            row.get::<uuid::Uuid>(0)
                .unwrap_or_else(|_| oidc_core::utils::generate_uuid_v7())
        }
    };

    // 2. Admin user
    info!("Step 2/4: admin user...");
    let user_id = {
        let mut conn = wasi_pg_client::Connection::connect(&config)
            .await
            .context("seed: connect for user")?;
        let check = conn
            .query_params(
                "SELECT id FROM users WHERE realm_id = $1 AND email = $2 AND deleted_at IS NULL",
                &[&realm_id, &"admin@localhost"],
            )
            .await?;
        let rows = check.into_rows();
        if rows.is_empty() {
            let id = oidc_core::utils::generate_uuid_v7();
            let hasher = oidc_core::traits::hasher::Argon2idHasher::new();
            let password_hash = hasher
                .hash("admin")
                .map_err(|e| anyhow::anyhow!("hash failed: {e}"))?;
            conn.execute_params(
                r#"INSERT INTO users (id, realm_id, email, email_verified, username, password_hash, given_name, family_name, enabled)
                   VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"#,
                &[&id, &realm_id, &"admin@localhost", &true, &"admin", &Some(password_hash), &Some("Admin"), &Some("User"), &true],
            ).await?;
            info!("Created admin user (admin@localhost / admin)");
            id
        } else {
            let row = rows.into_iter().next().unwrap();
            row.get::<uuid::Uuid>(0)
                .unwrap_or_else(|_| oidc_core::utils::generate_uuid_v7())
        }
    };

    // 3. Client
    info!("Step 3/4: OIDC client...");
    {
        let mut conn = wasi_pg_client::Connection::connect(&config)
            .await
            .context("seed: connect for client")?;
        let check = conn
            .query_params(
                "SELECT id FROM clients WHERE client_id = $1",
                &[&"admin-ui"],
            )
            .await?;
        let rows = check.into_rows();
        if rows.is_empty() {
            let id = oidc_core::utils::generate_uuid_v7();
            let redirect_uris = serde_json::json!([
                format!("http://localhost:{}/callback", proxy_port),
                format!("http://localhost:{}/admin/callback", proxy_port)
            ]);
            let scopes = serde_json::json!(["openid", "profile", "email"]);
            let grant_types = serde_json::json!(["authorization_code", "refresh_token"]);
            conn.execute_params(
                r#"INSERT INTO clients (id, realm_id, client_id, client_type, name, redirect_uris, allowed_scopes, allowed_grant_types, pkce_required, enabled)
                   VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)"#,
                &[&id, &realm_id, &"admin-ui", &"public", &"Admin UI", &redirect_uris, &scopes, &grant_types, &true, &true],
            ).await?;
            info!("Created 'admin-ui' OIDC client");
        }
    }

    // 4. API key — best effort, don't let it hang the whole startup
    info!("Step 4/4: admin API key...");
    let api_key_result = tokio::time::timeout(Duration::from_secs(10), async {
        let mut conn = wasi_pg_client::Connection::connect(&config)
            .await
            .context("seed: connect for api key")?;
        let check = conn.query_params("SELECT id FROM api_keys WHERE NOT revoked LIMIT 1", &[]).await?;
        let rows = check.into_rows();
        if rows.is_empty() {
            let id = oidc_core::utils::generate_uuid_v7();
            let prefix = "oidc_adm";
            let raw_secret = format!("{}_{}", prefix, oidc_core::utils::generate_opaque_token().map_err(|e| anyhow::anyhow!("token gen failed: {e}"))?);
            let hasher = oidc_core::traits::hasher::Argon2idHasher::new();
            let hashed_secret = hasher.hash(&raw_secret).map_err(|e| anyhow::anyhow!("hash failed: {e}"))?;
            let scopes = serde_json::json!(["admin"]);
            conn.execute_params(
                r#"INSERT INTO api_keys (id, realm_id, name, prefix, hashed_secret, scopes, revoked, request_count, created_by)
                   VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"#,
                &[&id, &realm_id, &"Dev Admin Key", &prefix, &hashed_secret, &scopes, &false, &0i64, &Some(user_id)],
            ).await?;
            info!("═══════════════════════════════════════════════════════════════");
            info!("  ADMIN API KEY (save this — shown only once):");
            info!("  {}", raw_secret);
            info!("═══════════════════════════════════════════════════════════════");
        } else {
            info!("Admin API key already exists.");
        }
        Ok::<_, anyhow::Error>(())
    }).await;

    match api_key_result {
        Ok(Ok(())) => {}
        Ok(Err(e)) => warn!("API key seed failed (non-fatal): {e}"),
        Err(_) => warn!("API key seed timed out (non-fatal), continuing..."),
    }

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
        .stdout(Stdio::null())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn().context("failed to start backend")?;

    let stderr = child.stderr.take().unwrap();
    tokio::spawn(stream_logs("backend", stderr));

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
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-API-Key');

    if (req.method === 'OPTIONS') {{
        res.writeHead(200);
        res.end();
        return;
    }}

    const isApi = req.url.startsWith('/api/') || req.url.startsWith('/oidc/') || req.url.startsWith('/.well-known/') || req.url.startsWith('/health');
    const target = isApi ? `http://127.0.0.1:${{BACKEND_PORT}}` : `http://127.0.0.1:${{FRONTEND_PORT}}`;

    proxy.web(req, res, {{ target }}, (err) => {{
        console.error('Proxy error:', err.message);
        res.writeHead(502);
        res.end('Bad Gateway');
    }});
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

    let stderr = child.stderr.take().unwrap();
    tokio::spawn(stream_logs("proxy", stderr));

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

async fn stream_logs(name: &str, stderr: tokio::process::ChildStderr) {
    let reader = BufReader::new(stderr);
    let mut lines = reader.lines();

    while let Ok(Some(line)) = lines.next_line().await {
        debug!("[{name}] {line}");
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
