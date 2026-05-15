//! Test application builder.
//!
//! Spawns the full Axum application on a random port backed by a real
//! PostgreSQL database, seeds baseline test data, and provides a
//! `reqwest` client for making HTTP requests in integration tests.

use oidc_repository::repositories::{
    client_repo::ClientRepo, realm_repo::RealmRepo, user_repo::UserRepo,
};
use uuid::Uuid;

use crate::harness::database_url;
use crate::helpers::fixtures;

/// Generate RSA (PKCS#1) and Ed25519 (PKCS#8) PEM strings once, cached.
fn test_signing_keys() -> &'static (String, String) {
    use std::sync::OnceLock;
    static KEYS: OnceLock<(String, String)> = OnceLock::new();
    KEYS.get_or_init(|| {
        use rand::rngs::OsRng;
        use rand::RngCore;

        // RSA 2048-bit → PKCS#1 PEM
        let rsa_key = rsa::RsaPrivateKey::new(&mut OsRng, 2048)
            .expect("failed to generate RSA key");
        use rsa::pkcs1::EncodeRsaPrivateKey;
        let rsa_pem: String = rsa_key
            .to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)
            .expect("failed to serialize RSA key")
            .to_string();

        // Ed25519 → PKCS#8 PEM
        let mut secret_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut secret_bytes);
        let ed_key = ed25519_dalek::SigningKey::from_bytes(&secret_bytes);
        use pkcs8::EncodePrivateKey;
        let ed_pem: String = ed_key
            .to_pkcs8_pem(pkcs8::LineEnding::LF)
            .expect("failed to serialize Ed25519 key")
            .to_string();

        (rsa_pem, ed_pem)
    })
}

// ===================================================================
// TestApp
// ===================================================================

/// Counter for unique per-test database names.
static TEST_COUNTER: std::sync::Mutex<u64> = std::sync::Mutex::new(0);

/// A running test application instance.
///
/// Each test gets its own **fresh PostgreSQL database** (created from the
/// migrated template) and a dedicated Axum server on a random port.
/// This provides perfect isolation without `TRUNCATE` races.
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
    /// The per-test database URL (e.g. `postgresql://.../oidc_hub_test_1`).
    db_url: String,
    /// Sender half of a oneshot channel — when dropped, signals the
    /// server task to shut down.
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
    /// Handle to the server task so we can await its shutdown.
    server_handle: Option<tokio::task::JoinHandle<()>>,
}

impl TestApp {
    /// Create a new test application.
    ///
    /// This will:
    /// 1. Get the shared database URL from the harness.
    /// 2. Create a **fresh per-test database** from the migrated template.
    /// 3. Seed a master realm, admin user, and `admin-ui` client.
    /// 4. Build the Axum router with an explicit config (no env vars).
    /// 5. Spawn the server on `127.0.0.1:0` (random port).
    /// 6. Return a `TestApp` with the base URL and HTTP client.
    pub async fn new() -> Self {
        let db_url = database_url().await;

        // -----------------------------------------------------------------
        // 1. Create a fresh per-test database
        // -----------------------------------------------------------------
        let db_name = {
            let mut guard = TEST_COUNTER.lock().unwrap();
            *guard += 1;
            format!("oidc_hub_test_{}", *guard)
        };

        let test_db_url = create_test_database(&db_url, &db_name).await;

        // -----------------------------------------------------------------
        // 2. Seed baseline data
        // -----------------------------------------------------------------
        let (master_realm_id, master_user_email) = {
            let config =
                wasi_pg_client::Config::from_uri(&test_db_url).expect("invalid test database URL");
            let pg_conn = wasi_pg_client::Connection::connect(&config)
                .await
                .expect("failed to connect to test database");
            let mut conn = oidc_repository::connection::Connection::from_pg_client(pg_conn);
            let (id, email) = seed_baseline_data(&mut conn).await;
            let _ = conn.close().await;
            (id, email)
        };

        // -----------------------------------------------------------------
        // 3. Spawn server on a random port
        // -----------------------------------------------------------------
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("failed to bind random port");
        let port = listener
            .local_addr()
            .expect("failed to get local addr")
            .port();

        let issuer = format!("http://localhost:{port}");

        // Build the router with an explicit config so there is NO env-var
        // race when tests run in parallel.
        let config = {
            let (rsa_pem, ed_pem) = test_signing_keys();
            openid_connect_wasi::state::AppConfig {
                database_url: test_db_url.clone(),
                bind_address: "127.0.0.1".to_string(),
                port,
                issuer: issuer.clone(),
                encryption_key: fixtures::TEST_ENCRYPTION_KEY.to_string(),
                pairwise_salt: "test-pairwise-salt".to_string(),
                signing_key: Some(rsa_pem.clone()),
                ed25519_key: Some(ed_pem.clone()),
            }
        };
        let app = openid_connect_wasi::app_router_with_config(config);

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

        let server_handle = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = shutdown_rx.await;
                })
                .await
                .expect("test server failed");
        });

        let base_url = format!("http://127.0.0.1:{port}");

        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("failed to build reqwest client");

        Self {
            base_url,
            client,
            master_realm_id,
            master_user_email,
            db_url: test_db_url,
            shutdown_tx: Some(shutdown_tx),
            server_handle: Some(server_handle),
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

    /// Open a fresh auto-commit connection to this test's isolated database.
    ///
    /// Use this for direct SQL / repo calls that must be visible to the app
    /// server (e.g. `UPDATE clients SET ...`).
    pub async fn db_conn(&self) -> oidc_repository::connection::Connection {
        let config = wasi_pg_client::Config::from_uri(&self.db_url).expect("invalid database URL");
        let pg_conn = wasi_pg_client::Connection::connect(&config)
            .await
            .expect("failed to connect to test database");
        oidc_repository::connection::Connection::from_pg_client(pg_conn)
    }

    /// Seed a user directly in the database and return its ID.
    ///
    /// The password is hashed using Argon2id.
    pub async fn seed_user(&self, email: &str, password: &str) -> Uuid {
        let mut conn = self.db_conn().await;
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
        let mut conn = self.db_conn().await;
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
        let mut conn = self.db_conn().await;
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
        let mut conn = self.db_conn().await;
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
        let mut conn = self.db_conn().await;
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
        // Signal the server to shut down by dropping the sender.
        if let Some(tx) = self.shutdown_tx.take() {
            drop(tx);
        }
        // Abort the server task to ensure it doesn't hold DB connections.
        if let Some(handle) = self.server_handle.take() {
            handle.abort();
        }
    }
}

/// Create a fresh per-test database from the migrated template.
///
/// 1. Connects to the shared server using the admin `postgres` database.
/// 2. Creates a new database named `db_name` from the `oidc_hub_test` template.
/// 3. Returns a connection URL pointing to the new database.
async fn create_test_database(base_url: &str, db_name: &str) -> String {
    // Parse the base URL to extract host, port, user, password.
    let parsed = url::Url::parse(base_url).expect("invalid database URL");
    let host = parsed.host_str().unwrap_or("localhost");
    let port = parsed.port().unwrap_or(5432);
    let user = parsed.username();
    let password = parsed.password().unwrap_or("postgres");

    // Connect to the default `postgres` database to issue CREATE DATABASE.
    let admin_url = format!("postgresql://{user}:{password}@{host}:{port}/postgres");
    let config = wasi_pg_client::Config::from_uri(&admin_url).expect("invalid admin URL");
    let mut conn = wasi_pg_client::Connection::connect(&config)
        .await
        .expect("failed to connect to postgres admin database");

    // Drop if exists (cleanup from previous crashed run), then create from template.
    let drop_sql = format!("DROP DATABASE IF EXISTS \"{db_name}\"");
    let create_sql =
        format!("CREATE DATABASE \"{db_name}\" WITH TEMPLATE = 'oidc_hub_test' OWNER = '{user}'");

    let _ = conn.execute(&drop_sql).await;
    conn.execute(&create_sql)
        .await
        .expect("failed to create test database from template");

    let _ = conn.close().await;

    // Return the connection URL for the new database.
    format!("postgresql://{user}:{password}@{host}:{port}/{db_name}")
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
