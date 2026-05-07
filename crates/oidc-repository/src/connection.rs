//! Database connection abstraction.

use tracing::debug;

/// A database connection wrapper.
/// Uses `wasi-pg-client` on both native (via tokio-transport) and WASM.
pub struct Connection {
    inner: wasi_pg_client::Connection,
}

impl Connection {
    /// Create a new connection from a `pg_client` connection.
    pub fn from_pg_client(conn: wasi_pg_client::Connection) -> Self {
        debug!("created pg_client connection");
        Self { inner: conn }
    }

    /// Access the underlying connection.
    pub fn inner(&self) -> &wasi_pg_client::Connection {
        &self.inner
    }
}
