use axum::Json;
use axum::extract::{Path, Query, State};
use oidc_core::OidcError;
use oidc_repository::repositories::organization_repo::OrganizationRepo;
use oidc_repository::repositories::realm_repo::RealmRepo;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::state::OidcState;

#[derive(Debug, Deserialize)]
pub struct OrganizationIdentityProviderQuery {
    pub email: String,
}

pub async fn discover_identity_provider(
    State(state): State<OidcState>,
    Path(realm): Path<String>,
    Query(query): Query<OrganizationIdentityProviderQuery>,
) -> Result<Json<Value>, OidcError> {
    let domain = query
        .email
        .rsplit_once('@')
        .map(|(_, domain)| domain.trim().to_ascii_lowercase())
        .filter(|domain| !domain.is_empty())
        .ok_or_else(|| OidcError::InvalidInput("a valid email address is required".into()))?;
    let mut conn = state.connect().await?;
    let realm = RealmRepo
        .find_by_name(&mut conn, &realm)
        .await?
        .filter(|realm| realm.enabled)
        .ok_or_else(|| OidcError::NotFound("realm".into()))?;
    let provider = OrganizationRepo
        .find_identity_provider_for_domain(&mut conn, realm.id, &domain)
        .await?;
    Ok(Json(match provider {
        Some(provider) => json!({
            "identity_provider": {
                "alias": provider.alias,
                "display_name": provider.display_name,
            }
        }),
        None => json!({"identity_provider": null}),
    }))
}
