//! Test application builder.
//!
//! Spawns the full Axum application on a random port backed by a real
//! PostgreSQL database, seeds baseline test data, and provides a
//! `reqwest` client for making HTTP requests in integration tests.

use std::sync::OnceLock;

use oidc_core::traits::Hasher;
use oidc_repository::repositories::{
    client_repo::ClientRepo, realm_repo::RealmRepo, user_repo::UserRepo,
};
use uuid::Uuid;

use crate::harness::{clean_database, database_url, test_conn_no_tx};
use crate::helpers::fixtures;

// ===================================================================
// TestApp
// ===================================================================

/// Global singleton test server — spawned once and reused by every `TestApp`.
/// This removes the per-test server startup overhead (~200-500 ms).
///
/// The server runs on a **dedicated background thread** with its own Tokio
/// runtime so it survives the end of individual `#[tokio::test]` functions.
struct GlobalServer {
    base_url: String,
    client: reqwest::Client,
    /// Keep the background runtime alive for the whole test run.
    _runtime: std::thread::JoinHandle<()>,
    /// Owned sender so we can signal shutdown if desired.
    _shutdown_tx: tokio::sync::oneshot::Sender<()>,
}

static GLOBAL_SERVER: OnceLock<GlobalServer> = OnceLock::new();

/// A running test application instance.
///
/// Uses a **globally shared** OIDC Hub server to avoid spawning a new
/// Axum instance for every test.  Each test still gets its own clean
/// database state (via `clean_database` + `seed_baseline_data`).
///
/// # Example
///
/// ```ignore
/// let app = TestApp::new().await;
/// let resp = app.client().get(&format!("{}/health", app.url())).send().await.unwrap();
/// assert!(resp.status().is_success());
/// ```
pub struct TestApp {
    /// Base URL of the running server (e.g. `http://127.0.0.1:39421`).
    base_url: String,
    /// HTTP client with redirect policy set to `none` (to inspect redirects).
    client: reqwest::Client,
    /// The master realm seeded during setup.
    master_realm_id: Uuid,
    /// The admin user email seeded during setup.
    master_user_email: String,
}

impl TestApp {
    /// Create a new test application.
    ///
    /// This will:
    /// 1. Get (or spawn) the **global** shared server.
    /// 2. Clean the database.
    /// 3. Seed a master realm, admin user, and `admin-ui` client.
    /// 4. Return a `TestApp` with the global base URL and HTTP client.
    pub async fn new() -> Self {
        let db_url = database_url().await;

        // -----------------------------------------------------------------
        // Global server — spawned once on a background thread, reused by all tests
        // -----------------------------------------------------------------
        if GLOBAL_SERVER.get().is_none() {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("failed to bind random port");
            let port = listener
                .local_addr()
                .expect("failed to get local addr")
                .port();

            let issuer = format!("http://localhost:{port}");

            // SAFETY: Tests run single-threaded (--test-threads=1).
            unsafe {
                std::env::set_var("RUST_LOG", "oidc_oidc=trace,oidc_repository=trace,trace");
                std::env::set_var("OIDC_DATABASE_URL", &db_url);
                std::env::set_var("OIDC_ENCRYPTION_KEY", fixtures::TEST_ENCRYPTION_KEY);
                std::env::set_var("OIDC_ISSUER", &issuer);
                std::env::set_var("OIDC_SERVER_PORT", port.to_string());
                std::env::set_var("OIDC_SERVER_BIND_ADDRESS", "127.0.0.1");
                std::env::set_var("OIDC_CORS_ORIGINS", "http://localhost:3000");
            }

            let app = openid_connect_wasi::app_router();
            let base_url = format!("http://127.0.0.1:{port}");
            let client = reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("failed to build reqwest client");

            // Use a tokio oneshot channel for shutdown — the receiver is !Send,
            // but we only use it inside the async block on the background thread.
            let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
            // Wrap the receiver in a std::sync::Mutex so it can be moved into the thread
            let shutdown_rx = std::sync::Mutex::new(Some(shutdown_rx));

            let bg_thread = std::thread::spawn(move || {
                let rt =
                    tokio::runtime::Runtime::new().expect("failed to create background runtime");
                rt.block_on(async move {
                    let rx = shutdown_rx.lock().unwrap().take().unwrap();
                    axum::serve(listener, app)
                        .with_graceful_shutdown(async {
                            let _ = rx.await;
                        })
                        .await
                        .expect("test server failed");
                });
            });

            let _ = GLOBAL_SERVER.set(GlobalServer {
                base_url,
                client,
                _runtime: bg_thread,
                _shutdown_tx: shutdown_tx,
            });
        }

        let global = GLOBAL_SERVER.get().unwrap();

        // -----------------------------------------------------------------
        // Per-test database reset (single connection for TRUNCATE + seed)
        // -----------------------------------------------------------------
        let (master_realm_id, master_user_email) = {
            let mut conn = test_conn_no_tx().await;
            clean_database(&mut conn)
                .await
                .expect("clean_database failed");
            let (id, email) = seed_baseline_data(&mut conn).await;
            let _ = conn.close().await;
            (id, email)
        };

        Self {
            base_url: global.base_url.clone(),
            client: global.client.clone(),
            master_realm_id,
            master_user_email,
        }
    }

    /// The base URL of the running test server.
    ///
    /// E.g. `http://127.0.0.1:39421`
    pub fn url(&self) -> String {
        self.base_url.clone()
    }

    /// The HTTP client (redirect policy: none).
    pub fn client(&self) -> &reqwest::Client {
        &self.client
    }

    /// The master realm ID seeded during setup.
    pub fn master_realm_id(&self) -> Uuid {
        self.master_realm_id
    }

    /// The admin user email seeded during setup.
    pub fn master_user_email(&self) -> &str {
        &self.master_user_email
    }

    /// Seed a user directly in the database and return its ID.
    ///
    /// The password is hashed using Argon2id.
    pub async fn seed_user(&self, email: &str, password: &str) -> Uuid {
        let mut conn = test_conn_no_tx().await;
        let user = fixtures::test_user(self.master_realm_id, email, password);
        let id = user.id;
        UserRepo
            .create(&mut conn, &user)
            .await
            .expect("failed to seed user");
        let _ = conn.close().await;
        id
    }

    /// Seed a disabled user directly in the database and return its ID.
    ///
    /// The password is hashed using Argon2id. The user's `enabled` field
    /// is set to `false`.
    pub async fn seed_disabled_user(&self, email: &str, password: &str) -> Uuid {
        let mut conn = test_conn_no_tx().await;
        let mut user = fixtures::test_user(self.master_realm_id, email, password);
        user.enabled = false;
        let id = user.id;
        UserRepo
            .create(&mut conn, &user)
            .await
            .expect("failed to seed disabled user");
        let _ = conn.close().await;
        id
    }

    /// Seed a client directly in the database and return its ID.
    ///
    /// `client_type` should be `"confidential"` or `"public"`.
    /// `redirect_uris` are the allowed redirect URIs for the client.
    pub async fn seed_client(
        &self,
        client_id: &str,
        client_type: &str,
        redirect_uris: &[&str],
    ) -> Uuid {
        let mut conn = test_conn_no_tx().await;
        let mut client = fixtures::test_client(
            self.master_realm_id,
            client_id,
            redirect_uris.iter().map(|s| s.to_string()).collect(),
        );

        if client_type == "public" {
            client.client_type = oidc_core::models::ClientType::Public;
        }

        let id = client.id;
        ClientRepo
            .create(&mut conn, &client)
            .await
            .expect("failed to seed client");
        let _ = conn.close().await;
        id
    }

    /// Seed a confidential client with a known secret and return its ID.
    ///
    /// The `client_secret` is hashed using Argon2id and stored in
    /// `client_secret_hash`.  This is required for token, introspect,
    /// and revoke endpoints that need client authentication.
    pub async fn seed_client_with_secret(
        &self,
        client_id: &str,
        client_secret: &str,
        redirect_uris: &[&str],
    ) -> Uuid {
        let mut conn = test_conn_no_tx().await;
        let mut client = fixtures::test_client(
            self.master_realm_id,
            client_id,
            redirect_uris.iter().map(|s| s.to_string()).collect(),
        );

        let hasher = oidc_core::traits::hasher::Argon2idHasher::new();
        let hash = <dyn oidc_core::traits::Hasher>::hash(&hasher, client_secret)
            .expect("failed to hash client secret");
        client.client_secret_hash = Some(hash);

        let id = client.id;
        ClientRepo
            .create(&mut conn, &client)
            .await
            .expect("failed to seed client with secret");
        let _ = conn.close().await;
        id
    }

    /// Seed a **public** client (no secret) for implicit/hybrid flow tests.
    pub async fn seed_public_client(&self, client_id: &str, redirect_uris: &[&str]) -> Uuid {
        let mut conn = test_conn_no_tx().await;
        let client = fixtures::test_public_client(
            self.master_realm_id,
            client_id,
            redirect_uris.iter().map(|s| s.to_string()).collect(),
        );

        let id = client.id;
        ClientRepo
            .create(&mut conn, &client)
            .await
            .expect("failed to seed public client");
        let _ = conn.close().await;
        id
    }
}

impl Drop for TestApp {
    fn drop(&mut self) {
        // No-op: the server is global and stays alive for the whole test run.
        // This avoids the ~50-100 ms abort/shutdown overhead per test.
    }
}
// ===================================================================

/// Seed the baseline data required for all tests:
/// - A "master" realm  (the PasswordFlow expects this exact name)
/// - An admin user with the fixed test email
/// - An `admin-ui` client
///
/// Returns (realm_id, user_email).
async fn seed_baseline_data(conn: &mut oidc_repository::Connection) -> (Uuid, String) {
    // Master realm — PasswordFlow::execute does
    //   RealmRepo.find_by_name("master").await
    // so the name must match exactly.
    let realm = fixtures::test_realm("master");
    let realm_id = realm.id;
    RealmRepo
        .create(conn, &realm)
        .await
        .expect("failed to seed master realm");

    // Admin user — use the FIXED test email so `login()` can find it.
    let user = fixtures::test_user(
        realm_id,
        fixtures::TEST_USER_EMAIL,
        fixtures::TEST_USER_PASSWORD,
    );
    UserRepo
        .create(conn, &user)
        .await
        .expect("failed to seed admin user");

    // Admin UI client — PasswordFlow::execute defaults to "admin-ui"
    // so the client_id must match exactly.
    let client = fixtures::test_client(
        realm_id,
        "admin-ui",
        vec!["http://localhost:3000/callback".to_string()],
    );
    ClientRepo
        .create(conn, &client)
        .await
        .expect("failed to seed admin-ui client");

    (realm_id, fixtures::TEST_USER_EMAIL.to_string())
}
