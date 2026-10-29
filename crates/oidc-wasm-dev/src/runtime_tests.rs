//! P3 runtime checks exposed by the existing WASM development CLI.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use axum::body::Bytes;
use axum::extract::Path as RoutePath;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use reqwest::Client;
use serde_json::Value;
use tokio::net::{TcpListener, TcpStream};
use tokio::process::{Child, Command};
use tokio::sync::Mutex;
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::{sleep, timeout};
use tracing::{info, warn};

use super::{BACKEND_WASM, FRONTEND_WASM, WasmDevState};

const PROBE: &str = "target/wasm32-wasip2/release/examples/http_client_smoke.wasm";

pub async fn run(state: &Arc<Mutex<WasmDevState>>, args: &[String]) -> Result<()> {
    let skip_build = match args {
        [] => false,
        [flag] if flag == "--skip-build" => true,
        _ => anyhow::bail!("Usage: oidc-wasm-dev runtime-test [--skip-build]"),
    };
    if !skip_build {
        super::build_frontend().await?;
        super::build_wasm_package(FRONTEND_WASM).await?;
        super::build_wasm_package(BACKEND_WASM).await?;
        let status = Command::new("cargo")
            .args([
                "build",
                "--locked",
                "-p",
                "oidc-wasi-http",
                "--example",
                "http-client-smoke",
                "--target",
                "wasm32-wasip2",
                "--release",
            ])
            .status()
            .await
            .context("building the outbound HTTP runtime probe")?;
        ensure!(status.success(), "outbound HTTP runtime probe build failed");
    }
    for artifact in [
        super::wasm_component_path(BACKEND_WASM),
        super::wasm_component_path(FRONTEND_WASM),
        PROBE.into(),
    ] {
        ensure!(
            root().join(&artifact).is_file(),
            "missing {artifact}; run runtime-test without --skip-build"
        );
    }
    let db_url = match std::env::var("OIDC_DATABASE_URL") {
        Ok(url) => url,
        Err(_) => super::start_database(state).await?,
    };
    let result = run_checks(&db_url).await;
    // Only this invocation's optional database belongs to this command. Leave
    // the normal dev stack, proxy and runtime-state file alone.
    drop(state.lock().await.db_container.take());
    result
}

async fn run_checks(db_url: &str) -> Result<()> {
    timeout(Duration::from_secs(65), super::wait_for_postgres(db_url))
        .await
        .context("test PostgreSQL did not become ready")??;
    let (rsa, ed25519) = super::generate_dev_signing_keys().await?;
    let nonce = || {
        format!(
            "{}{}",
            uuid::Uuid::new_v4().simple(),
            uuid::Uuid::new_v4().simple()
        )
    };
    let mut env = vec![
        ("OIDC_DATABASE_URL".into(), db_url.into()),
        ("OIDC_ENCRYPTION_KEY".into(), nonce()),
        ("OIDC_PAIRWISE_SALT".into(), nonce()),
        (
            "OIDC_ISSUER".into(),
            "http://localhost/runtime-smoke".into(),
        ),
        ("OIDC_SIGNING_KEY".into(), rsa),
        ("OIDC_ED25519_KEY".into(), ed25519),
    ];
    let client = Client::builder().timeout(Duration::from_secs(15)).build()?;
    let backend = Component::start(&super::wasm_component_path(BACKEND_WASM), &env).await?;
    let live = get_json(&client, &backend.url("/health/live"), StatusCode::OK).await?;
    ensure!(live["status"] == "alive", "unexpected liveness response");
    let ready = get_json(&client, &backend.url("/health/ready"), StatusCode::OK).await?;
    ensure!(
        ready["checks"]["database"] == "ok",
        "PostgreSQL readiness failed"
    );
    backend.stop().await?;
    info!("P3 backend: liveness and PostgreSQL readiness passed");

    check_database_deadline(&client, &env).await?;

    let frontend = Component::start(&super::wasm_component_path(FRONTEND_WASM), &env).await?;
    let response = client.get(frontend.url("/admin/")).send().await?;
    ensure!(
        response.status() == StatusCode::OK,
        "admin HTML request failed"
    );
    ensure!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.contains("text/html")),
        "expected admin HTML content type"
    );
    ensure!(!response.bytes().await?.is_empty(), "admin HTML is empty");
    let response = client.get(frontend.url("/js/index.js")).send().await?;
    ensure!(
        response.status() == StatusCode::OK && !response.bytes().await?.is_empty(),
        "admin JavaScript request failed"
    );
    frontend.stop().await?;
    info!("P3 admin: embedded HTML and JavaScript passed");

    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let echo_url = format!("http://{}", listener.local_addr()?);
    let router = axum::Router::new().route("/{mode}", post(echo));
    let _echo = BackgroundTask(tokio::spawn(async move {
        if let Err(error) = axum::serve(listener, router).await {
            warn!("runtime HTTP fixture stopped: {error}");
        }
    }));
    env.push(("OIDC_SMOKE_HTTP_URL".into(), echo_url));
    let probe = Component::start(PROBE, &env).await?;
    for payload in [Vec::new(), b"p3-stream".repeat(8192)] {
        let response = client
            .post(probe.url("/200"))
            .body(payload.clone())
            .send()
            .await?;
        ensure!(
            response.status() == StatusCode::OK,
            "outbound HTTP echo failed"
        );
        let cookies: Vec<_> = response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .collect();
        ensure!(
            cookies == ["first=1", "second=2"],
            "duplicate response headers were lost"
        );
        ensure!(
            response.bytes().await?.as_ref() == payload,
            "streamed HTTP body changed"
        );
    }
    let response = client
        .post(probe.url("/503"))
        .body("upstream error")
        .send()
        .await?;
    ensure!(
        response.status() == StatusCode::SERVICE_UNAVAILABLE
            && response.bytes().await? == "upstream error",
        "upstream HTTP error was not preserved"
    );
    let response = client.post(probe.url("/large")).body("").send().await?;
    ensure!(
        response.status() == StatusCode::BAD_GATEWAY,
        "oversized response was not rejected"
    );
    probe.stop().await?;
    info!("P3 outbound HTTP: streamed bodies, headers, status codes and response limit passed");
    Ok(())
}

async fn check_database_deadline(client: &Client, env: &[(String, String)]) -> Result<()> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let db_url = format!(
        "postgresql://smoke:smoke@{}/smoke?sslmode=disable",
        listener.local_addr()?
    );
    let connected = Arc::new(AtomicBool::new(false));
    let accepted = connected.clone();
    let _stalled = BackgroundTask(tokio::spawn(async move {
        let mut connections = JoinSet::new();
        while let Ok((stream, _)) = listener.accept().await {
            accepted.store(true, Ordering::SeqCst);
            connections.spawn(async move {
                let _stream = stream;
                std::future::pending::<()>().await;
            });
        }
    }));
    let mut stalled_env = env.to_vec();
    stalled_env.retain(|(name, _)| name != "OIDC_DATABASE_URL");
    stalled_env.push(("OIDC_DATABASE_URL".into(), db_url));
    let backend = Component::start(&super::wasm_component_path(BACKEND_WASM), &stalled_env).await?;
    let body = get_json(
        client,
        &backend.url("/health/ready"),
        StatusCode::SERVICE_UNAVAILABLE,
    )
    .await?;
    ensure!(
        connected.load(Ordering::SeqCst),
        "database TCP connection was never opened"
    );
    ensure!(
        body["checks"]["database"] == "failed",
        "unresponsive database must fail readiness"
    );
    backend.stop().await?;
    info!("P3 clocks: readiness cancels an unresponsive PostgreSQL connection");
    Ok(())
}

async fn get_json(client: &Client, url: &str, expected: StatusCode) -> Result<Value> {
    let response = client.get(url).send().await?;
    ensure!(
        response.status() == expected,
        "unexpected HTTP status for {url}: {}",
        response.status()
    );
    response.json().await.context("invalid JSON response")
}

async fn echo(RoutePath(mode): RoutePath<String>, headers: HeaderMap, body: Bytes) -> Response {
    if headers
        .get(header::AUTHORIZATION)
        .is_none_or(|value| value != "Bearer runtime-smoke")
    {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let status = if mode == "503" {
        StatusCode::SERVICE_UNAVAILABLE
    } else {
        StatusCode::OK
    };
    let body = if mode == "large" {
        Bytes::from(vec![b'x'; 16 * 1024 * 1024 + 1])
    } else {
        body
    };
    let mut response = (status, body).into_response();
    response
        .headers_mut()
        .append(header::SET_COOKIE, HeaderValue::from_static("first=1"));
    response
        .headers_mut()
        .append(header::SET_COOKIE, HeaderValue::from_static("second=2"));
    response
}

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

struct Component {
    child: Child,
    port: u16,
}

impl Component {
    async fn start(artifact: &str, env: &[(String, String)]) -> Result<Self> {
        let port = portpicker::pick_unused_port().context("no available runtime test port")?;
        let log_path = root().join("target").join(format!(
            "wasi-runtime-{}.log",
            Path::new(artifact).file_stem().unwrap().to_string_lossy()
        ));
        let log = std::fs::File::create(&log_path)?;
        let mut command = super::wasmtime_serve_command("127.0.0.1", port);
        let child = command
            .envs(env.iter().map(|(key, value)| (key, value)))
            .arg(root().join(artifact))
            .stdout(Stdio::from(log.try_clone()?))
            .stderr(Stdio::from(log))
            .kill_on_drop(true)
            .spawn()
            .context("starting Wasmtime; ensure it is on PATH")?;
        let mut component = Self { child, port };
        timeout(Duration::from_secs(45), async {
            loop {
                ensure!(
                    component.child.try_wait()?.is_none(),
                    "Wasmtime exited before accepting connections"
                );
                if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
                    return Ok::<_, anyhow::Error>(());
                }
                sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .with_context(|| format!("Wasmtime startup timed out; see {}", log_path.display()))?
        .with_context(|| format!("Wasmtime startup failed; see {}", log_path.display()))?;
        Ok(component)
    }

    fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{path}", self.port)
    }

    async fn stop(mut self) -> Result<()> {
        self.child
            .kill()
            .await
            .context("stopping runtime test component")
    }
}

struct BackgroundTask(JoinHandle<()>);

impl Drop for BackgroundTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}
