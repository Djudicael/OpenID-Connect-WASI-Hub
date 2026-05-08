//! Helper functions for mapping between `pg_client` types and domain models.

use oidc_core::OidcError;
use uuid::Uuid;
use wasi_pg_client::PgError;
use wasi_pg_client::Row;

/// Convert a `PgError` into an `OidcError::Internal`.
pub fn pg_err(e: PgError) -> OidcError {
    OidcError::Internal(e.to_string())
}

/// Extract a `Vec<String>` from a JSONB column.
pub fn json_string_vec(row: &Row, idx: usize) -> Result<Vec<String>, OidcError> {
    let val: serde_json::Value = row.get(idx).map_err(pg_err)?;
    match val {
        serde_json::Value::Array(arr) => arr
            .into_iter()
            .map(|v| match v {
                serde_json::Value::String(s) => Ok(s),
                _ => Ok(v.to_string()),
            })
            .collect::<Result<Vec<_>, _>>(),
        serde_json::Value::String(s) if s.is_empty() => Ok(Vec::new()),
        _ => Ok(Vec::new()),
    }
}

/// Serialize a `Vec<String>` into a JSONB value for parameter binding.
pub fn to_json_value_vec(v: &[String]) -> serde_json::Value {
    serde_json::Value::Array(
        v.iter()
            .map(|s| serde_json::Value::String(s.clone()))
            .collect(),
    )
}

/// Extract a required `Uuid` from a row column.
pub fn uuid(row: &Row, idx: usize) -> Result<Uuid, OidcError> {
    row.get::<uuid::Uuid>(idx).map_err(pg_err)
}

/// Extract an optional `Uuid` from a row column.
pub fn opt_uuid(row: &Row, idx: usize) -> Result<Option<Uuid>, OidcError> {
    row.get::<Option<uuid::Uuid>>(idx).map_err(pg_err)
}

/// Extract a required `String` from a row column.
pub fn string(row: &Row, idx: usize) -> Result<String, OidcError> {
    row.get::<String>(idx).map_err(pg_err)
}

/// Extract an optional `String` from a row column.
pub fn opt_string(row: &Row, idx: usize) -> Result<Option<String>, OidcError> {
    row.get::<Option<String>>(idx).map_err(pg_err)
}

/// Extract a required `bool` from a row column.
pub fn bool_(row: &Row, idx: usize) -> Result<bool, OidcError> {
    row.get::<bool>(idx).map_err(pg_err)
}

/// Extract a required `i64` from a row column.
pub fn i64_(row: &Row, idx: usize) -> Result<i64, OidcError> {
    row.get::<i64>(idx).map_err(pg_err)
}

/// Extract an optional `i64` from a row column.
pub fn opt_i64(row: &Row, idx: usize) -> Result<Option<i64>, OidcError> {
    row.get::<Option<i64>>(idx).map_err(pg_err)
}

/// Extract a required `DateTime<Utc>` from a row column.
pub fn datetime(row: &Row, idx: usize) -> Result<chrono::DateTime<chrono::Utc>, OidcError> {
    row.get::<chrono::DateTime<chrono::Utc>>(idx)
        .map_err(pg_err)
}

/// Extract an optional `DateTime<Utc>` from a row column.
pub fn opt_datetime(
    row: &Row,
    idx: usize,
) -> Result<Option<chrono::DateTime<chrono::Utc>>, OidcError> {
    row.get::<Option<chrono::DateTime<chrono::Utc>>>(idx)
        .map_err(pg_err)
}

/// Extract a required `Vec<u8>` from a row column.
pub fn bytes(row: &Row, idx: usize) -> Result<Vec<u8>, OidcError> {
    row.get::<Vec<u8>>(idx).map_err(pg_err)
}

/// Extract an optional `Vec<u8>` from a row column.
pub fn opt_bytes(row: &Row, idx: usize) -> Result<Option<Vec<u8>>, OidcError> {
    row.get::<Option<Vec<u8>>>(idx).map_err(pg_err)
}
