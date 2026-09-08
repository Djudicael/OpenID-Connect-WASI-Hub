use crate::state::OidcState;
use oidc_core::traits::token_service::{AccessTokenExtraClaims, IdTokenExtraClaims, TokenService};
use oidc_core::utils::{generate_opaque_token, generate_sid, generate_uuid_v7, sha2_256_hex};
use oidc_core::{
    OidcError,
    models::{CIBA_GRANT_TYPE, Session},
};
use oidc_repository::repositories::{
    ciba_repo::CibaRepo, client_repo::ClientRepo, session_repo::SessionRepo, user_repo::UserRepo,
};
use oidc_repository::{mapper::pg_err, with_transaction};
use serde_json::{Value, json};

pub struct CibaFlow;

enum CibaOutcome {
    Tokens(Value),
    ProtocolError(OidcError),
}

impl CibaFlow {
    pub async fn execute(
        state: &OidcState,
        auth_req_id: &str,
        client_id: &str,
        dpop_jkt: Option<&str>,
    ) -> Result<Value, OidcError> {
        let mut conn = state.connect().await?;
        let outcome = with_transaction!(conn, pg_err, {
            let mut request = CibaRepo
                .find_for_update(&mut conn, &sha2_256_hex(auth_req_id))
                .await?
                .ok_or(OidcError::ExpiredToken)?;
            if request.expires_at <= chrono::Utc::now() {
                CibaRepo.expire(&mut conn, request.id).await?;
                return Ok(CibaOutcome::ProtocolError(OidcError::ExpiredToken));
            }
            let client = ClientRepo
                .find_by_id(&mut conn, request.client_id)
                .await?
                .filter(|c| c.enabled)
                .ok_or(OidcError::InvalidClient)?;
            if client.client_id != client_id {
                return Err(OidcError::InvalidClient);
            }
            match request.status.as_str() {
                "pending" => {
                    if let Some(last) = request.last_polled_at
                        && chrono::Utc::now()
                            < last + chrono::Duration::seconds(request.interval_seconds as i64)
                    {
                        request.interval_seconds = (request.interval_seconds + 5).min(60);
                        CibaRepo
                            .record_poll(&mut conn, request.id, request.interval_seconds)
                            .await?;
                        return Ok(CibaOutcome::ProtocolError(OidcError::SlowDown));
                    }
                    CibaRepo
                        .record_poll(&mut conn, request.id, request.interval_seconds)
                        .await?;
                    return Ok(CibaOutcome::ProtocolError(OidcError::AuthorizationPending));
                }
                "denied" => {
                    return Err(OidcError::AuthorizationDenied(
                        "The user denied the authentication request".into(),
                    ));
                }
                "consumed" | "expired" => return Err(OidcError::ExpiredToken),
                "approved" => {}
                _ => return Err(OidcError::InvalidRequest),
            }
            let user = UserRepo
                .find_by_id(&mut conn, request.user_id)
                .await?
                .filter(|u| u.enabled)
                .ok_or_else(|| OidcError::NotFound("user".into()))?;
            let subject = if client.subject_type == "pairwise" {
                let sector = oidc_core::utils::extract_sector_identifier(
                    client.sector_identifier_uri.as_deref(),
                    &client.redirect_uris,
                )
                .unwrap_or_default();
                oidc_core::utils::compute_pairwise_sub(
                    &user.id.to_string(),
                    &sector,
                    &state.pairwise_salt,
                )
            } else {
                user.id.to_string()
            };
            let scopes = request.scope.clone();
            let organization =
                crate::organization_claims::resolve_organization_claim(&mut conn, user.id, &scopes)
                    .await?;
            let roles = crate::role_claims::resolve_role_claims(&mut conn, user.id).await?;
            let mapped = crate::protocol_mappers::resolve_mapped_claims(
                &mut conn,
                client.id,
                Some(&user),
                &scopes,
            )
            .await?;
            let include_roles = scopes.iter().any(|s| s == "roles");
            let service = state.token_service_for_realm(request.realm_id).await?;
            let access_token = service
                .issue_access_token_with_extra(
                    &subject,
                    &client.client_id,
                    &scopes,
                    dpop_jkt,
                    None,
                    None,
                    Some(AccessTokenExtraClaims {
                        custom_claims: mapped.access_token.clone(),
                        additional_audiences: mapped.access_audiences.clone(),
                        organization: organization.clone(),
                        realm_access: include_roles.then(|| roles.realm_access.clone()).flatten(),
                        resource_access: include_roles
                            .then(|| roles.resource_access.clone())
                            .flatten(),
                    }),
                )
                .await?;
            let mut id_custom = mapped.id_token;
            id_custom.insert(
                "urn:openid:params:jwt:claim:auth_req_id".into(),
                json!(auth_req_id),
            );
            let sid = generate_sid()?;
            let id_token = service
                .issue_id_token(
                    &subject,
                    &client.client_id,
                    Some(IdTokenExtraClaims {
                        custom_claims: id_custom,
                        additional_audiences: mapped.id_audiences,
                        nonce: None,
                        at_hash: Some(oidc_core::utils::compute_at_hash(&access_token)),
                        c_hash: None,
                        auth_time: request.auth_time.map(|v| v.timestamp()),
                        sid: Some(sid.clone()),
                        email: Some(user.email.clone()),
                        email_verified: Some(user.email_verified),
                        name: user.username.clone(),
                        given_name: user.given_name.clone(),
                        family_name: user.family_name.clone(),
                        middle_name: user.middle_name.clone(),
                        nickname: user.nickname.clone(),
                        preferred_username: user.preferred_username.clone(),
                        profile: user.profile.clone(),
                        picture: user.picture.clone(),
                        website: user.website.clone(),
                        gender: user.gender.clone(),
                        birthdate: user.birthdate.clone(),
                        zoneinfo: user.zoneinfo.clone(),
                        locale: Some(user.locale.clone()),
                        phone_number: user.phone_number.clone(),
                        phone_number_verified: user.phone_number_verified,
                        updated_at: Some(user.updated_at.timestamp()),
                        acr: request.acr.clone(),
                        amr: Some(request.amr.clone()),
                        azp: None,
                        address: None,
                        roles: roles.roles,
                        realm_access: roles.realm_access,
                        resource_access: roles.resource_access,
                        groups: None,
                        organization,
                    }),
                )
                .await?;
            let id_token = crate::flows::maybe_encrypt_id_token(state, &id_token, &client)?;
            let refresh_token = generate_opaque_token()?;
            let now = chrono::Utc::now();
            let session = Session {
                id: generate_uuid_v7(),
                sid,
                user_id: Some(user.id),
                realm_id: request.realm_id,
                client_id: client.id,
                grant_type: CIBA_GRANT_TYPE.into(),
                access_token_hash: sha2_256_hex(&access_token),
                refresh_token_hash: Some(sha2_256_hex(&refresh_token)),
                id_token_jti: None,
                scope: scopes.clone(),
                revoked: false,
                expires_at: now + chrono::Duration::minutes(15),
                refresh_expires_at: Some(now + chrono::Duration::days(7)),
                offline_session: false,
                offline_max_expires_at: None,
                created_at: now,
                last_used_at: None,
                token_family_id: Some(generate_uuid_v7()),
                previous_session_id: None,
                rotated_at: None,
                reused_at: None,
                family_revoked: false,
                authorization_details: None,
                resource: vec![],
                acr: request
                    .acr
                    .unwrap_or_else(|| oidc_core::utils::ACR_BRONZE.into()),
                amr: request.amr,
            };
            SessionRepo.create(&mut conn, &session).await?;
            CibaRepo.consume(&mut conn, request.id).await?;
            Ok(CibaOutcome::Tokens(
                json!({"access_token":access_token,"token_type":if dpop_jkt.is_some(){"DPoP"}else{"Bearer"},"expires_in":900,"refresh_token":refresh_token,"id_token":id_token,"scope":scopes.join(" ")}),
            ))
        })?;
        match outcome {
            CibaOutcome::Tokens(tokens) => Ok(tokens),
            CibaOutcome::ProtocolError(error) => Err(error),
        }
    }
}
