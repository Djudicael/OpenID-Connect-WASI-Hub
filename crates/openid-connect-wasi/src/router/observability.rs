//! Opt-in, realm-bound internal gauges. No process-local counters or background tasks.
use crate::state::AppState;
use axum::{
    Extension, Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    routing::get,
};
use oidc_core::utils::pkce::{s256_challenge, verify_s256};
use serde_json::{Value, json};
use std::time::Duration;

#[derive(Clone)]
pub(super) struct ExportConfig {
    realm: String,
    challenge: String,
}

impl ExportConfig {
    pub(super) fn new(realm: String, token: &str) -> Option<Self> {
        if realm.is_empty()
            || realm.len() > 100
            || !realm
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
            || token.len() != 64
            || !token.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return None;
        }
        Some(Self {
            realm,
            challenge: s256_challenge(token),
        })
    }
    pub(super) fn permits(&self, realm: &str, headers: &HeaderMap) -> bool {
        let mut values = headers.get_all(header::AUTHORIZATION).iter();
        let token = values
            .next()
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "));
        realm == self.realm
            && values.next().is_none()
            && token.is_some_and(|token| token.len() == 64 && verify_s256(token, &self.challenge))
    }
}

pub fn router() -> Router<AppState> {
    let token = std::env::var("OIDC_OBSERVABILITY_TOKEN").ok();
    let realm = std::env::var("OIDC_OBSERVABILITY_REALM").ok();
    match (realm, token) {
        (None, None) => Router::new(),
        (Some(realm), Some(token)) => {
            let config =
                ExportConfig::new(realm, &token).expect("invalid OIDC observability configuration");
            Router::new()
                .route("/api/v1/observability/realms/{realm}/metrics", get(metrics))
                .layer(Extension(config))
        }
        _ => panic!("configure both OIDC_OBSERVABILITY_REALM and OIDC_OBSERVABILITY_TOKEN"),
    }
}

async fn metrics(
    State(state): State<AppState>,
    Extension(config): Extension<ExportConfig>,
    Path(realm): Path<String>,
    headers: HeaderMap,
) -> Result<([(header::HeaderName, &'static str); 1], Json<Value>), StatusCode> {
    if !config.permits(&realm, &headers) {
        return Err(StatusCode::NOT_FOUND);
    }
    let result =
        super::health::run_with_timeout(Duration::from_secs(3), snapshot(&state, &realm)).await;
    let body = result
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    Ok(([(header::CACHE_CONTROL, "no-store")], Json(body)))
}

async fn snapshot(state: &AppState, realm: &str) -> Result<Value, wasi_pg_client::PgError> {
    let mut connection = wasi_pg_client::Connection::connect(&state.db_config).await?;
    connection.execute("SET statement_timeout='2000ms'").await?;
    let rows = connection.query_params("SELECT r.id::text, (SELECT count(*) FROM sessions s WHERE s.realm_id=r.id AND NOT s.revoked AND NOT s.family_revoked AND s.expires_at>now()), (SELECT count(*) FROM sessions s WHERE s.realm_id=r.id AND s.created_at>=now()-interval '5 minutes'), (SELECT count(*) FROM audit_events a WHERE a.realm_id=r.id AND a.created_at>=now()-interval '5 minutes' AND a.event_type='user.authenticated'), (SELECT count(*) FROM audit_events a WHERE a.realm_id=r.id AND a.created_at>=now()-interval '5 minutes' AND a.event_type='LOGIN_FAILURE') FROM realms r WHERE r.name=$1 AND r.enabled AND r.deleted_at IS NULL", &[&realm]).await?;
    let mut gauges = serde_json::Map::new();
    if let Some(row) = rows.iter().next() {
        for (index, name) in [
            "oidc.sessions.active",
            "oidc.sessions.created_5m",
            "oidc.auth.audit_successes_5m",
            "oidc.auth.audit_failures_5m",
        ]
        .iter()
        .enumerate()
        {
            gauges.insert((*name).into(), row.get::<i64>(index + 1)?.into());
        }
    }
    connection.close().await?;
    Ok(json!({"source":"hub-internal","realm":realm,"window_seconds":300,"gauges":gauges}))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn export_auth_is_realm_bound_and_rejects_duplicate_headers() {
        let token = "a".repeat(64);
        let config = ExportConfig::new("one".into(), &token).unwrap();
        let mut headers = HeaderMap::new();
        assert!(!config.permits("one", &headers));
        headers.insert(
            header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );
        assert!(config.permits("one", &headers));
        assert!(!config.permits("two", &headers));
        headers.append(header::AUTHORIZATION, "Bearer invalid".parse().unwrap());
        assert!(!config.permits("one", &headers));
        assert!(ExportConfig::new("one".into(), "short").is_none());
    }
}
