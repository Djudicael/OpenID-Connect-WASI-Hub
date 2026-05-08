//! Database connection abstraction.

use tracing::debug;
use wasi_pg_client::pg_types::ToSql;
use wasi_pg_client::{PgError, QueryResult, Row};

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

    /// Access the underlying connection mutably.
    pub fn inner_mut(&mut self) -> &mut wasi_pg_client::Connection {
        &mut self.inner
    }

    /// Execute a simple query and return all rows.
    pub async fn query(&mut self, sql: &str) -> Result<QueryResult, PgError> {
        self.inner.query(sql).await
    }

    /// Execute a parameterized query and return all rows.
    pub async fn query_params(
        &mut self,
        sql: &str,
        params: &[&dyn ToSql],
    ) -> Result<QueryResult, PgError> {
        self.inner.query_params(sql, params).await
    }

    /// Execute a query returning at most one row.
    pub async fn query_one(&mut self, sql: &str) -> Result<Option<Row>, PgError> {
        self.inner.query_one(sql).await
    }

    /// Execute a parameterized query returning at most one row.
    pub async fn query_one_params(
        &mut self,
        sql: &str,
        params: &[&dyn ToSql],
    ) -> Result<Option<Row>, PgError> {
        let result = self.inner.query_params(sql, params).await?;
        Ok(result.into_rows().into_iter().next())
    }

    /// Execute a statement (INSERT/UPDATE/DELETE) and return the command tag.
    pub async fn execute(&mut self, sql: &str) -> Result<wasi_pg_client::ExecuteResult, PgError> {
        self.inner.execute(sql).await
    }

    /// Execute a parameterized statement and return rows affected.
    pub async fn execute_params(
        &mut self,
        sql: &str,
        params: &[&dyn ToSql],
    ) -> Result<u64, PgError> {
        let result = self.inner.query_params(sql, params).await?;
        Ok(result.rows_affected().unwrap_or(0))
    }
}
