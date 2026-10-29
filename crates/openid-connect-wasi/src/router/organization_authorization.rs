//! Dedicated realm-scoped read capability for machine/project authorization.
use super::observability::ExportConfig;
use crate::state::AppState;
use axum::{
    Extension, Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    routing::get,
};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

pub fn router() -> Router<AppState> {
    match (
        std::env::var("OIDC_ORGANIZATION_STATUS_REALM").ok(),
        std::env::var("OIDC_ORGANIZATION_STATUS_TOKEN").ok(),
    ) {
        (None, None) => Router::new(),
        (Some(realm), Some(token)) => Router::new()
            .route(
                "/api/v1/authorization/realms/{realm}/organizations/{id}/status",
                get(status),
            )
            .layer(Extension(
                ExportConfig::new(realm, &token).expect("invalid organization read capability"),
            )),
        _ => panic!(
            "configure both OIDC_ORGANIZATION_STATUS_REALM and OIDC_ORGANIZATION_STATUS_TOKEN"
        ),
    }
}
#[derive(Default, Deserialize)]
struct Details {
    #[serde(default)]
    teams: bool,
}
async fn status(
    State(state): State<AppState>,
    Extension(config): Extension<ExportConfig>,
    Path((realm, id)): Path<(String, Uuid)>,
    Query(details): Query<Details>,
    headers: HeaderMap,
) -> Result<([(header::HeaderName, &'static str); 1], Json<Value>), StatusCode> {
    if !config.permits(&realm, &headers) {
        return Err(StatusCode::NOT_FOUND);
    }
    let result = super::health::run_with_timeout(
        std::time::Duration::from_secs(3),
        snapshot(&state, &realm, id, details.teams),
    )
    .await;
    let value = result
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    Ok(([(header::CACHE_CONTROL, "no-store")], Json(value)))
}
async fn snapshot(
    state: &AppState,
    realm: &str,
    id: Uuid,
    directory: bool,
) -> anyhow::Result<Value> {
    let mut connection = wasi_pg_client::Connection::connect(&state.db_config).await?;
    connection.execute("SET statement_timeout='2000ms'").await?;
    let rows=connection.query_params("SELECT EXISTS(SELECT 1 FROM organizations o JOIN realms r ON r.id=o.realm_id WHERE o.id=$1 AND r.name=$2 AND o.enabled AND o.deleted_at IS NULL AND r.enabled AND r.deleted_at IS NULL)",&[&id,&realm]).await?;
    let active = rows
        .iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing organization status"))?
        .get::<bool>(0)?;
    let mut teams = vec![];
    if active && directory {
        let rows=connection.query_params("SELECT g.id::text,g.name FROM organization_groups og JOIN organizations o ON o.id=og.organization_id JOIN realms r ON r.id=o.realm_id JOIN groups g ON g.id=og.group_id AND g.realm_id=o.realm_id AND g.deleted_at IS NULL WHERE o.id=$1 AND r.name=$2 ORDER BY g.id LIMIT 257",&[&id,&realm]).await?;
        for row in rows.iter() {
            teams.push(json!({"id":row.get::<String>(0)?,"name":row.get::<String>(1)?}));
        }
        anyhow::ensure!(
            teams.len() <= 256,
            "organization team directory exceeds limit"
        );
    }
    connection.close().await?;
    Ok(json!({"organization_id":id,"active":active,"teams":teams}))
}
