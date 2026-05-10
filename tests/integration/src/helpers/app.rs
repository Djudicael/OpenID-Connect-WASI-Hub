//! Test application builder.
//!
//! Spawns the full Axum application on a random port backed by a real
//! PostgreSQL database, seeds baseline test data, and provides a
//! `reqwest` client for making HTTP requests in integration tests.

use oidc_core::traits::Hasher;
use oidc_repository::repositories::{
    client_repo::ClientRepo, realm_repo::RealmRepo, user_repo::UserRepo,
};
use uuid::Uuid;

use crate::harness::{clean_database, database_url, test_conn};
use crate::helpers::fixtures;

// ===================================================================
// TestApp
// ===================================================================

/// A running test application instance.
///
/// Spawns the full OIDC Hub on a random port, seeds baseline data, and
/// provides an HTTP client for making requests.
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
}

impl TestApp {
    /// Create a new test application.
    ///
    /// This will:
    /// 1. Get the database URL from the test harness
    /// 2. Clean the database
    /// 3. Seed a master realm, admin user, and `admin-ui` client
    /// 4. Set env vars and build the Axum router
    /// 5. Spawn the server on `127.0.0.1:0` (random port)
    /// 6. Return a `TestApp` with the base URL and HTTP client
    pub async fn new() -> Self {
        let db_url = database_url().await;

        // Clean the database first
        {
            let mut conn = test_conn().await;
            clean_database(&mut conn)
                .await
                .expect("failed to clean database");
        }

        // Seed baseline data
        let master_realm_id = {
            let mut conn = test_conn().await;
            seed_baseline_data(&mut conn).await
        };

        // Set env vars so that `AppState::from_env()` picks up the test config.
        // We must set these before calling `app_router()`.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("failed to bind random port");
        let port = listener
            .local_addr()
            .expect("failed to get local addr")
            .port();

        let issuer = format!("http://localhost:{port}");

        // SAFETY: These env vars are set before any concurrent access in tests.
        // Tests run single-threaded (--test-threads=1).
        unsafe {
            std::env::set_var("OIDC_DATABASE_URL", &db_url);
            std::env::set_var("OIDC_ENCRYPTION_KEY", fixtures::TEST_ENCRYPTION_KEY);
            std::env::set_var("OIDC_ISSUER", &issuer);
            std::env::set_var("OIDC_SERVER_PORT", port.to_string());
            std::env::set_var("OIDC_SERVER_BIND_ADDRESS", "127.0.0.1");
            std::env::set_var("OIDC_CORS_ORIGINS", "http://localhost:3000");
        }

        let app = openid_connect_wasi::app_router();

        // Spawn the server
        tokio::spawn(async move {
            axum::serve(listener, app)
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

    /// Seed a user directly in the database and return its ID.
    ///
    /// The password is hashed using Argon2id.
    pub async fn seed_user(&self, email: &str, password: &str) -> Uuid {
        let mut conn = test_conn().await;
        let user = fixtures::test_user(self.master_realm_id, email, password);
        let id = user.id;
        UserRepo
            .create(&mut conn, &user)
            .await
            .expect("failed to seed user");
        id
    }

    /// Seed a disabled user directly in the database and return its ID.
    ///
    /// The password is hashed using Argon2id. The user's `enabled` field
    /// is set to `false`.
    pub async fn seed_disabled_user(&self, email: &str, password: &str) -> Uuid {
        let mut conn = test_conn().await;
        let mut user = fixtures::test_user(self.master_realm_id, email, password);
        user.enabled = false;
        let id = user.id;
        UserRepo
            .create(&mut conn, &user)
            .await
            .expect("failed to seed disabled user");
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
        let mut conn = test_conn().await;
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
        let mut conn = test_conn().await;
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
        id
    }
}

// ===================================================================
// Seed helpers
// ===================================================================

/// Seed the baseline data required for all tests:
/// - A `master` realm
/// - An admin user (`testadmin@localhost` / `TestPass123!`)
/// - An `admin-ui` client
///
/// Returns the master realm ID.
async fn seed_baseline_data(conn: &mut oidc_repository::Connection) -> Uuid {
    // Master realm
    let realm = fixtures::test_realm("master");
    let realm_id = realm.id;
    RealmRepo
        .create(conn, &realm)
        .await
        .expect("failed to seed master realm");

    // Admin user
    let user = fixtures::test_user(
        realm_id,
        fixtures::TEST_USER_EMAIL,
        fixtures::TEST_USER_PASSWORD,
    );
    UserRepo
        .create(conn, &user)
        .await
        .expect("failed to seed admin user");

    // Admin UI client
    let client = fixtures::test_client(
        realm_id,
        fixtures::TEST_CLIENT_ID,
        vec!["http://localhost:3000/callback".to_string()],
    );
    ClientRepo
        .create(conn, &client)
        .await
        .expect("failed to seed admin-ui client");

    realm_id
}
