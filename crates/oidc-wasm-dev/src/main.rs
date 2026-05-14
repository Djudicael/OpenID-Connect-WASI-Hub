//! OIDC WASM Dev Orchestrator — spins up PostgreSQL, seeds data,
//! builds the WASM component, builds the frontend, and serves both
//! via a proxy. This mimics the production JAMstack deployment where
//! static frontend files talk to the WASM backend.
//!
//! Usage:
//!   cargo run -p oidc-wasm-dev -- start    # Start DB + build WASM + build front + proxy
//!   cargo run -p oidc-wasm-dev -- stop     # Stop everything
//!   cargo run -p oidc-wasm-dev -- status   # Show status
//!   cargo run -p oidc-wasm-dev -- test     # Run smoke tests against WASM server
//!
//! Dev Credentials (seeded on first start):
//!   Admin login:    admin@example.com / Admin123
//!
//! When the process exits (Ctrl-C), the PostgreSQL container is automatically dropped.

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

const BACKEND_WASM: &str = "openid-connect-wasi";
const FRONTEND_DIR: &str = "front/admin";
const MIGRATIONS_DIR: &str = "migrations/postgresql";

const BIND_ADDRESS: &str = "0.0.0.0";

// ─── State ──────────────────────────────────────────────────────────────────

#[derive(Debug)]
struct WasmDevState {
    db_url: String,
    db_container: Option<rustainers::Container<rustainers::images::GenericImage>>,
    wasm_port: u16,
    proxy_port: u16,
    wasmtime: Option<Child>,
    proxy: Option<Child>,
}

impl WasmDevState {
    fn new(db_url: String, wasm_port: u16, proxy_port: u16) -> Self {
        Self {
            db_url,
            db_container: None,
            wasm_port,
            proxy_port,
            wasmtime: None,
            proxy: None,
        }
    }
}

// ─── Main ───────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(|s| s.as_str()).unwrap_or("start");

    let state = Arc::new(Mutex::new(WasmDevState::new(
        String::new(),
        pick_port(8080),
        pick_port(3000),
    )));

    match cmd {
        "start" => cmd_start(&state).await,
        "stop" => cmd_stop(&state).await,
        "status" => cmd_status(&state).await,
        "test" => cmd_test(&state).await,
        _ => {
            eprintln!("Usage: cargo run -p oidc-wasm-dev -- [start|stop|status|test]");
            std::process::exit(1);
        }
    }
}

// ─── Commands ───────────────────────────────────────────────────────────────

async fn cmd_start(state: &Arc<Mutex<WasmDevState>>) -> Result<()> {
    check_tools().await?;

    info!("═══════════════════════════════════════════════════════════════");
    info!("  OIDC WASM Dev Environment (JAMstack mode)");
    info!("  Target: wasm32-wasip2  |  Runtime: wasmtime serve");
    info!("  Frontend: static build served via proxy");
    info!("═══════════════════════════════════════════════════════════════");

    // 1. Start PostgreSQL
    let db_url = start_database(state).await?;
    {
        let mut s = state.lock().await;
        s.db_url = db_url.clone();
    }

    // 2. Run migrations
    run_migrations(&db_url).await?;

    // 3. Seed baseline data
    seed_data(&db_url, 8080).await?;

    // 4. Build frontend (static files for JAMstack testing)
    build_frontend().await?;

    // 5. Build WASM component
    build_wasm().await?;

    // 6. Start wasmtime serve
    start_wasmtime(state).await?;

    // 7. Start proxy (static frontend + API routes to wasmtime)
    start_proxy(state).await?;

    let proxy_port = state.lock().await.proxy_port;

    info!("═══════════════════════════════════════════════════════════════");
    info!("  WASM dev environment ready!");
    info!("");
    info!("  Proxy (use this):  http://localhost:{}", proxy_port);
    info!(
        "  Backend API:       http://localhost:{}",
        state.lock().await.wasm_port
    );
    info!(
        "  Discovery:         http://localhost:{}/.well-known/openid-configuration",
        proxy_port
    );
    info!(
        "  Realm login page:  http://localhost:{}/realms/master/login",
        proxy_port
    );
    info!("  Database:          {}", db_url);
    info!("");
    info!("  Press Ctrl-C to stop (container auto-drops)");
    info!("═══════════════════════════════════════════════════════════════");

    tokio::signal::ctrl_c().await?;
    info!("Shutting down...");
    shutdown_all(state).await;

    Ok(())
}

async fn cmd_stop(state: &Arc<Mutex<WasmDevState>>) -> Result<()> {
    shutdown_all(state).await;
    info!("Stopped.");
    Ok(())
}

async fn cmd_status(state: &Arc<Mutex<WasmDevState>>) -> Result<()> {
    let s = state.lock().await;
    info!("DB URL:     {}", s.db_url);
    info!("WASM Port:  {}", s.wasm_port);
    info!("Proxy Port: {}", s.proxy_port);
    info!(
        "Container:  {}",
        if s.db_container.is_some() {
            "running"
        } else {
            "none"
        }
    );
    info!(
        "Wasmtime:   {}",
        if s.wasmtime.is_some() {
            "running"
        } else {
            "none"
        }
    );
    info!(
        "Proxy:      {}",
        if s.proxy.is_some() { "running" } else { "none" }
    );
    Ok(())
}

async fn cmd_test(state: &Arc<Mutex<WasmDevState>>) -> Result<()> {
    // Quick smoke test against the running proxy (frontend + backend)
    let port: u16 = std::env::var("OIDC_PROXY_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| {
            let rt = tokio::runtime::Handle::try_current().expect("no runtime");
            rt.block_on(async { state.lock().await.proxy_port })
        });
    let base_url = format!("http://localhost:{}", port);

    info!("Running smoke tests against {}...", base_url);

    let client = reqwest::Client::new();
    let mut passed = 0u32;
    let mut failed = 0u32;

    // Test 1: Health endpoint
    match client.get(format!("{}/health", base_url)).send().await {
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

    // Test 2: Discovery document
    match client
        .get(format!("{}/.well-known/openid-configuration", base_url))
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

    // Test 3: JWKS endpoint
    match client.get(format!("{}/oidc/jwks", base_url)).send().await {
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

    // Test 4: Login with admin credentials
    match client
        .post(format!("{}/oidc/login", base_url))
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

    // Test 5: Per-realm discovery
    match client
        .get(format!(
            "{}/realms/master/.well-known/openid-configuration",
            base_url
        ))
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            let body: serde_json::Value = resp.json().await.unwrap_or_default();
            let issuer = body.get("issuer").and_then(|v| v.as_str()).unwrap_or("");
            if issuer.contains("/realms/master") {
                info!(
                    "  ✓ GET /realms/master/.well-known/openid-configuration → realm-scoped issuer"
                );
                passed += 1;
            } else {
                warn!("  ✗ realm discovery issuer missing realm path: {}", issuer);
                failed += 1;
            }
        }
        Ok(resp) => {
            warn!(
                "  ✗ GET /realms/master/.well-known/openid-configuration → {}",
                resp.status()
            );
            failed += 1;
        }
        Err(e) => {
            warn!(
                "  ✗ GET /realms/master/.well-known/openid-configuration → {}",
                e
            );
            failed += 1;
        }
    }

    // Test 6: Realm login page HTML
    match client
        .get(format!("{}/realms/master/login", base_url))
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            let body = resp.text().await.unwrap_or_default();
            if body.contains("<!DOCTYPE html>") && body.contains("<form") {
                info!("  ✓ GET /realms/master/login → branded HTML page");
                passed += 1;
            } else {
                warn!("  ✗ GET /realms/master/login → missing HTML or form");
                failed += 1;
            }
        }
        Ok(resp) => {
            warn!("  ✗ GET /realms/master/login → {}", resp.status());
            failed += 1;
        }
        Err(e) => {
            warn!("  ✗ GET /realms/master/login → {}", e);
            failed += 1;
        }
    }

    // Test 7: Admin UI static files served by proxy
    match client.get(format!("{}/", base_url)).send().await {
        Ok(resp) if resp.status().is_success() => {
            let body = resp.text().await.unwrap_or_default();
            if body.contains("<!DOCTYPE html>") {
                info!("  ✓ GET / → Admin UI HTML served");
                passed += 1;
            } else {
                warn!("  ✗ GET / → missing HTML");
                failed += 1;
            }
        }
        Ok(resp) => {
            warn!("  ✗ GET / → {}", resp.status());
            failed += 1;
        }
        Err(e) => {
            warn!("  ✗ GET / → {}", e);
            failed += 1;
        }
    }

    // Test 8: Admin UI JS bundle served
    match client.get(format!("{}/dist/app.js", base_url)).send().await {
        Ok(resp) if resp.status().is_success() => {
            info!("  ✓ GET /dist/app.js → static JS served");
            passed += 1;
        }
        Ok(resp) => {
            warn!("  ✗ GET /dist/app.js → {}", resp.status());
            failed += 1;
        }
        Err(e) => {
            warn!("  ✗ GET /dist/app.js → {}", e);
            failed += 1;
        }
    }

    info!("");
    info!("═══════════════════════════════════════════════════════════════");
    info!("  Smoke test results: {} passed, {} failed", passed, failed);
    if failed == 0 {
        info!("  All tests passed! ✓");
    } else {
        warn!(
            "  Some tests failed. Is the server running? Try: cargo run -p oidc-wasm-dev -- start"
        );
    }
    info!("═══════════════════════════════════════════════════════════════");

    if failed > 0 {
        std::process::exit(1);
    }
    Ok(())
}

// ─── Tool Checks ───────────────────────────────────────────────────────────

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

    Ok(())
}

// ─── Database ───────────────────────────────────────────────────────────────

async fn start_database(state: &Arc<Mutex<WasmDevState>>) -> Result<String> {
    info!("Starting PostgreSQL container via rustainers...");

    let runner = Runner::podman().context("Failed to create Podman runner")?;

    let image_name = ImageName::new_with_tag(DB_IMAGE, DB_TAG);
    let mut image = rustainers::images::GenericImage::new(image_name);
    image.add_env_var("POSTGRES_DB", DB_NAME);
    image.add_env_var("POSTGRES_USER", DB_USER);
    image.add_env_var("POSTGRES_PASSWORD", DB_PASSWORD);
    image.add_port_mapping(5432);
    image.set_container_name("oidc-hub-wasm-postgres");

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

    let migrations_dir = std::path::Path::new(MIGRATIONS_DIR);
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

async fn seed_data(db_url: &str, _proxy_port: u16) -> Result<()> {
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
                    "http://localhost:3000/callback".to_string(),
                    "http://localhost:3000/admin/callback".to_string(),
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
            };
            repo.create(&mut conn, &client)
                .await
                .map_err(|e| anyhow::anyhow!("client create: {e}"))?;
            info!(
                "Created 'test-service' confidential client (client_id: test-service, client_secret: test-service-secret)"
            );
        }
    }

    // 4. API key — best effort
    info!("Step 4/5: admin API key...");
    let api_key_result = tokio::time::timeout(Duration::from_secs(10), async {
        let pg_conn = wasi_pg_client::Connection::connect(&config)
            .await
            .context("seed: connect for api key")?;
        let mut conn = oidc_repository::Connection::from_pg_client(pg_conn);

        let repo = oidc_repository::repositories::api_key_repo::ApiKeyRepo;
        let existing = repo
            .find_by_realm(&mut conn, realm_id, false)
            .await
            .map_err(|e| anyhow::anyhow!("api key lookup: {e}"))?;
        if !existing.is_empty() {
            info!("Admin API key already exists.");
            return Ok::<_, anyhow::Error>(());
        }

        let (_api_key, raw_key) = oidc_apikey::ApiKeyService::generate_key(
            &mut conn,
            realm_id,
            "WASM Dev Admin Key".into(),
            vec!["admin".into()],
            None,
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

// ─── WASM Build ─────────────────────────────────────────────────────────────

async fn build_wasm() -> Result<()> {
    info!("Building WASM component (wasm32-wasip2)...");

    let build = Command::new("cargo")
        .args([
            "build",
            "-p",
            BACKEND_WASM,
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
    Ok(())
}

// ─── Wasmtime Serve ─────────────────────────────────────────────────────────

async fn start_wasmtime(state: &Arc<Mutex<WasmDevState>>) -> Result<()> {
    let port = {
        let s = state.lock().await;
        s.wasm_port
    };
    let db_url = {
        let s = state.lock().await;
        s.db_url.clone()
    };

    let encryption_key =
        "2a3131371e4b5559606b70777e858f969da4acb3babec5ccc3cdd5dddbe3e9f0".to_string();

    // Generate deterministic dev signing keys so all WASM instances share the
    // same keys. Without this, wasmtime serve creates fresh instances per
    // request and random startup keys break token verification (SSO fails).
    let (rsa_pem, ed25519_pem) = generate_dev_signing_keys().await?;

    let wasm_path = format!(
        "target/wasm32-wasip2/release/{}.wasm",
        BACKEND_WASM.replace("-", "_")
    );

    info!("Starting wasmtime serve on port {port}...");

    // NOTE: --max-instance-reuse-count=1000 keeps the same WASM instance alive
    // across requests so the random JWT signing keys generated at startup are
    // reused. Without this, every request gets a fresh instance with new keys,
    // and tokens issued by instance N fail verification on instance N+1.
    //
    // PRODUCTION: Do NOT rely on instance reuse. Instead set OIDC_SIGNING_KEY
    // and OIDC_ED25519_KEY env vars so every instance loads the same
    // deterministic keys. See JwtTokenService::new for key-generation commands.
    let mut cmd = Command::new("wasmtime");
    cmd.arg("serve")
        .arg("--addr")
        .arg(format!("{BIND_ADDRESS}:{port}"))
        .arg("--max-instance-reuse-count")
        .arg("1000")
        .arg("--idle-instance-timeout")
        .arg("300s")
        .arg("-S")
        .arg("cli=y")
        .arg("-S")
        .arg("inherit-env=y")
        .arg("-S")
        .arg("inherit-network=y")
        .arg("-S")
        .arg("tcp=y")
        .arg("-S")
        .arg("allow-ip-name-lookup=y")
        .arg("--env")
        .arg(format!("OIDC_DATABASE_URL={}", &db_url))
        .arg("--env")
        .arg(format!("OIDC_SERVER_PORT={}", port))
        .arg("--env")
        .arg(format!("OIDC_SERVER_BIND_ADDRESS={}", BIND_ADDRESS))
        .arg("--env")
        .arg(format!("OIDC_ENCRYPTION_KEY={}", &encryption_key))
        .arg("--env")
        .arg(format!("OIDC_SIGNING_KEY={}", &rsa_pem))
        .arg("--env")
        .arg("OIDC_SIGNING_KID=key-1")
        .arg("--env")
        .arg(format!("OIDC_ED25519_KEY={}", &ed25519_pem))
        .arg("--env")
        .arg("OIDC_ED25519_KID=ed-key-1")
        .arg("--env")
        .arg(format!("OIDC_ISSUER=http://localhost:{}", port))
        .arg("--env")
        .arg("OIDC_RATE_LIMIT_MAX=1000")
        .arg("--env")
        .arg("OIDC_RATE_LIMIT_WINDOW_SECS=60")
        .arg("--env")
        .arg("RUST_LOG=trace")
        .arg(&wasm_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn().context("failed to start wasmtime serve")?;

    let stderr = child.stderr.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    tokio::spawn(stream_logs("wasmtime", stderr));
    tokio::spawn(stream_logs("wasmtime-out", stdout));

    let health_url = format!("http://127.0.0.1:{port}/health");
    wait_for_http(&health_url, 30).await?;

    {
        let mut s = state.lock().await;
        s.wasmtime = Some(child);
    }

    info!("wasmtime serve ready at http://localhost:{port}");
    Ok(())
}

// ─── Frontend Build ─────────────────────────────────────────────────────────

async fn build_frontend() -> Result<()> {
    info!("Building frontend (JAMstack static files)...");

    let frontend_dir = std::path::Path::new(FRONTEND_DIR);
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

    info!("Frontend built to {}/dist/", FRONTEND_DIR);
    Ok(())
}

// ─── Proxy ──────────────────────────────────────────────────────────────────

async fn start_proxy(state: &Arc<Mutex<WasmDevState>>) -> Result<()> {
    let (wasm_port, proxy_port) = {
        let s = state.lock().await;
        (s.wasm_port, s.proxy_port)
    };

    info!("Starting proxy on port {proxy_port}...");

    let proxy_modules_dir = std::env::temp_dir().join("oidc-wasm-proxy-modules");
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
const fs = require('fs');
const url = require('url');

const proxy = httpProxy.createProxyServer({{}});
const PROXY_PORT = {proxy_port};
const BACKEND_PORT = {backend_port};
const BIND_ADDRESS = '{bind}';
const FRONTEND_DIR = '{frontend_dir}';

// MIME type map for static files
const mimeTypes = {{
    '.html': 'text/html',
    '.js': 'application/javascript',
    '.css': 'text/css',
    '.json': 'application/json',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.gif': 'image/gif',
    '.svg': 'image/svg+xml',
    '.ico': 'image/x-icon',
    '.woff': 'font/woff',
    '.woff2': 'font/woff2',
    '.ttf': 'font/ttf',
}};

function serveStatic(req, res, filePath) {{
    const ext = path.extname(filePath).toLowerCase();
    const contentType = mimeTypes[ext] || 'application/octet-stream';

    fs.readFile(filePath, (err, data) => {{
        if (err) {{
            if (err.code === 'ENOENT') {{
                // SPA fallback: serve index.html for unknown paths
                const indexPath = path.join(FRONTEND_DIR, 'index.html');
                fs.readFile(indexPath, (err2, indexData) => {{
                    if (err2) {{
                        res.writeHead(404);
                        res.end('Not found');
                        return;
                    }}
                    res.setHeader('Content-Type', 'text/html');
                    res.writeHead(200);
                    res.end(indexData);
                }});
                return;
            }}
            res.writeHead(500);
            res.end('Server error');
            return;
        }}
        res.setHeader('Content-Type', contentType);
        res.writeHead(200);
        res.end(data);
    }});
}}

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

    const isApi = req.url.startsWith('/api/') || req.url.startsWith('/oidc/') || req.url.startsWith('/.well-known/') || req.url.startsWith('/health') || req.url.startsWith('/realms/');

    if (isApi) {{
        const target = `http://127.0.0.1:${{BACKEND_PORT}}`;
        console.log(`[proxy] ${{req.method}} ${{req.url}} -> BACKEND (${{target}})`);
        proxy.web(req, res, {{ target }}, (err) => {{
            console.error('Proxy error:', err.message);
            if (!res.headersSent) {{
                res.writeHead(502);
                res.end('Bad Gateway');
            }}
        }});
    }} else {{
        // Serve static frontend files from dist/
        let filePath = path.join(FRONTEND_DIR, req.url === '/' ? 'index.html' : req.url);
        console.log(`[proxy] ${{req.method}} ${{req.url}} -> STATIC (${{filePath}})`);
        serveStatic(req, res, filePath);
    }}
}});

// Add CORS headers to every proxied response
proxy.on('proxyRes', (proxyRes, req, res) => {{
    proxyRes.headers['access-control-allow-origin'] = '*';
    proxyRes.headers['access-control-allow-methods'] = 'GET, POST, PUT, DELETE, OPTIONS';
    proxyRes.headers['access-control-allow-headers'] = 'Content-Type, Authorization, X-API-Key, X-CSRF-Token';
}});

proxy.on('error', (err, req, res) => {{
    if (res && !res.headersSent) {{
        res.writeHead(502);
        res.end('Bad Gateway');
    }}
}});

server.listen(PROXY_PORT, BIND_ADDRESS, () => {{
    console.log(`Proxy running at http://${{BIND_ADDRESS}}:${{PROXY_PORT}}`);
    console.log(`Serving static files from ${{FRONTEND_DIR}}`);
    console.log(`Proxying API to http://127.0.0.1:${{BACKEND_PORT}}`);
}});
"#,
        proxy_port = proxy_port,
        backend_port = wasm_port,
        bind = BIND_ADDRESS,
        frontend_dir = std::path::Path::new(FRONTEND_DIR)
            .join("dist")
            .canonicalize()
            .unwrap_or_else(|_| std::path::Path::new(FRONTEND_DIR).join("dist"))
            .to_string_lossy()
            .replace("\\", "/")
    );

    let proxy_path = std::env::temp_dir().join("oidc-wasm-proxy.js");
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

// ─── Shutdown ───────────────────────────────────────────────────────────────

async fn shutdown_all(state: &Arc<Mutex<WasmDevState>>) {
    let mut s = state.lock().await;

    if let Some(mut proxy) = s.proxy.take() {
        info!("Stopping proxy...");
        let _ = proxy.kill().await;
    }

    if let Some(mut wasmtime) = s.wasmtime.take() {
        info!("Stopping wasmtime...");
        let _ = wasmtime.kill().await;
    }

    if s.db_container.take().is_some() {
        info!("PostgreSQL container dropped.");
    }

    let proxy_path = std::env::temp_dir().join("oidc-wasm-proxy.js");
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

/// Generate or reuse cached dev signing keys (RSA 2048 + Ed25519) via openssl.
/// Keys are stored in the system temp directory so they survive across restarts.
async fn generate_dev_signing_keys() -> Result<(String, String)> {
    let tmp = std::env::temp_dir();
    let rsa_path = tmp.join("oidc-wasm-dev-rsa.pem");
    let ed25519_path = tmp.join("oidc-wasm-dev-ed25519.pem");

    // If both files exist and look valid, reuse them.
    if rsa_path.exists() && ed25519_path.exists() {
        let rsa_pem = tokio::fs::read_to_string(&rsa_path)
            .await
            .with_context(|| format!("reading cached RSA key: {}", rsa_path.display()))?;
        let ed25519_pem = tokio::fs::read_to_string(&ed25519_path)
            .await
            .with_context(|| format!("reading cached Ed25519 key: {}", ed25519_path.display()))?;

        // Sanity-check: RSA PEM must contain the PKCS#1 label.
        if rsa_pem.contains("RSA PRIVATE KEY") && ed25519_pem.contains("PRIVATE KEY") {
            return Ok((rsa_pem, ed25519_pem));
        }
        // Corrupted / wrong-format cache — delete and regenerate.
        let _ = tokio::fs::remove_file(&rsa_path).await;
        let _ = tokio::fs::remove_file(&ed25519_path).await;
    }

    // Generate RSA key in PKCS#1 format (required by the `rsa` crate).
    // We use a two-step approach for compatibility with both OpenSSL 1.x and 3.x:
    // 1. genpkey always outputs PKCS#8
    // 2. `openssl rsa -traditional` converts PKCS#8 → PKCS#1
    let rsa_pkcs8_path = tmp.join("oidc-wasm-dev-rsa-pkcs8.pem");
    let gen_status = Command::new("openssl")
        .arg("genpkey")
        .arg("-algorithm")
        .arg("RSA")
        .arg("-pkeyopt")
        .arg("rsa_keygen_bits:2048")
        .arg("-out")
        .arg(&rsa_pkcs8_path)
        .status()
        .await
        .context("spawning openssl genpkey -algorithm RSA")?;
    if !gen_status.success() {
        anyhow::bail!(
            "openssl genpkey -algorithm RSA failed (exit code: {:?})",
            gen_status.code()
        );
    }
    let conv_status = Command::new("openssl")
        .arg("rsa")
        .arg("-in")
        .arg(&rsa_pkcs8_path)
        .arg("-out")
        .arg(&rsa_path)
        .arg("-traditional")
        .status()
        .await
        .context("spawning openssl rsa -traditional")?;
    if !conv_status.success() {
        anyhow::bail!(
            "openssl rsa -traditional failed (exit code: {:?})",
            conv_status.code()
        );
    }
    let _ = tokio::fs::remove_file(&rsa_pkcs8_path).await;

    // Generate Ed25519 key (PKCS#8 format — required by ed25519-dalek)
    let ed25519_status = Command::new("openssl")
        .arg("genpkey")
        .arg("-algorithm")
        .arg("Ed25519")
        .arg("-out")
        .arg(&ed25519_path)
        .status()
        .await
        .context("spawning openssl genpkey -algorithm Ed25519")?;
    if !ed25519_status.success() {
        anyhow::bail!(
            "openssl genpkey -algorithm Ed25519 failed (exit code: {:?})",
            ed25519_status.code()
        );
    }

    let rsa_pem = tokio::fs::read_to_string(&rsa_path)
        .await
        .with_context(|| format!("reading generated RSA key: {}", rsa_path.display()))?;
    let ed25519_pem = tokio::fs::read_to_string(&ed25519_path)
        .await
        .with_context(|| format!("reading generated Ed25519 key: {}", ed25519_path.display()))?;

    Ok((rsa_pem, ed25519_pem))
}
