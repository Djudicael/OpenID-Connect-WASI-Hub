//! SAML 2.0 browser SSO and identity brokering.

use std::time::{Duration, SystemTime};

use axum::http::{HeaderMap, StatusCode, header::LOCATION};
use axum::response::{Html, IntoResponse, Response};
use chrono::{DateTime, Utc};
use oidc_core::models::{
    IdentityProvider as BrokerProvider, SamlPendingRequest, SamlRealmKey, SamlServiceProvider,
    Session, User,
};
use oidc_repository::repositories::{
    client_repo::ClientRepo, identity_provider_repo::IdentityProviderRepo, realm_repo::RealmRepo,
    saml_repo::SamlRepo, session_repo::SessionRepo, user_repo::UserRepo,
};
use rand::{RngCore, rngs::OsRng};
use rsa::pkcs8::EncodePrivateKey as _;
use saml::{
    Attribute, AuthnContextClassRef, Binding, C14nAlgorithm, ConsumeAuthnRequest,
    ConsumeLogoutRequest, ConsumeResponse, DataEncryptionAlgorithm, DigestAlgorithm, Dispatch,
    Endpoint, IdentityProvider, IdentityProviderConfig, IdpAssertionSigning, IdpDescriptor,
    IdpLogoutSigning, IdpLogoutWantSigned, IssueResponse, KeyPair, KeyTransportAlgorithm,
    LoginTracker, LogoutStatus, NameId, NameIdFormat, PeerCryptoPolicy, ReplayMode,
    ServiceProvider, ServiceProviderConfig, SignatureAlgorithm, SpDescriptor, SpLogoutSigning,
    SpLogoutWantSigned, SpWantSigned, SsoResponseBinding, SsoResponseEndpoint, StartLogin,
    WireDirection, decode_wire,
};
use sha2::{Digest, Sha256};

use crate::{session_cookie, state::OidcState};

const FLOW_TTL_MINUTES: i64 = 10;

fn saml_error(status: StatusCode, message: impl Into<String>) -> Response {
    (
        status,
        Html(format!(
            "<!doctype html><title>SAML error</title><h1>SAML sign-in failed</h1><p>{}</p>",
            html_escape(&message.into())
        )),
    )
        .into_response()
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn random_token() -> String {
    use base64::Engine as _;
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn token_hash(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

async fn authenticated_user(
    state: &OidcState,
    headers: &HeaderMap,
    realm_id: uuid::Uuid,
) -> Result<Option<(User, oidc_core::models::Session)>, oidc_core::OidcError> {
    let key = state.decode_encryption_key()?;
    let Some(raw) = session_cookie::extract_session_id_from_headers(headers, &key) else {
        return Ok(None);
    };
    let Ok(id) = uuid::Uuid::parse_str(&raw) else {
        return Ok(None);
    };
    let mut conn = state.connect().await?;
    let Some(session) = SessionRepo.find_by_id(&mut conn, id).await? else {
        return Ok(None);
    };
    if session.realm_id != realm_id || session.revoked || session.expires_at <= Utc::now() {
        return Ok(None);
    }
    let Some(user_id) = session.user_id else {
        return Ok(None);
    };
    Ok(UserRepo
        .find_by_id(&mut conn, user_id)
        .await?
        .filter(|u| u.enabled)
        .map(|u| (u, session)))
}

async fn realm_key(
    state: &OidcState,
    realm_id: uuid::Uuid,
) -> Result<KeyPair, oidc_core::OidcError> {
    let mut conn = state.connect().await?;
    let stored = match SamlRepo.get_key(&mut conn, realm_id).await? {
        Some(v) => v,
        None => {
            let rsa = rsa::RsaPrivateKey::new(&mut OsRng, 2048).map_err(|e| {
                oidc_core::OidcError::Internal(format!("SAML key generation failed: {e}"))
            })?;
            let pem = rsa
                .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
                .map_err(|e| {
                    oidc_core::OidcError::Internal(format!("SAML key encoding failed: {e}"))
                })?
                .to_string();
            let certificate_key = rcgen::KeyPair::from_pem(&pem).map_err(|e| {
                oidc_core::OidcError::Internal(format!("SAML certificate key failed: {e}"))
            })?;
            let params = rcgen::CertificateParams::new(vec!["OpenID Connect Hub SAML".to_string()])
                .map_err(|e| {
                    oidc_core::OidcError::Internal(format!(
                        "SAML certificate parameters failed: {e}"
                    ))
                })?;
            let certificate = params.self_signed(&certificate_key).map_err(|e| {
                oidc_core::OidcError::Internal(format!("SAML certificate generation failed: {e}"))
            })?;
            let row = SamlRealmKey {
                realm_id,
                private_key_encrypted: state.encrypt_sensitive_value(pem.as_bytes())?,
                certificate_pem: certificate.pem(),
                created_at: Utc::now(),
                updated_at: Utc::now(),
            };
            SamlRepo.create_key(&mut conn, &row).await?;
            SamlRepo
                .get_key(&mut conn, realm_id)
                .await?
                .ok_or_else(|| {
                    oidc_core::OidcError::Internal("SAML realm key was not persisted".into())
                })?
        }
    };
    let private = state.decrypt_sensitive_value(&stored.private_key_encrypted)?;
    let cert = saml::X509Certificate::from_pem(stored.certificate_pem.as_bytes()).map_err(|e| {
        oidc_core::OidcError::Internal(format!("invalid SAML realm certificate: {e}"))
    })?;
    Ok(KeyPair::from_pkcs8_pem(&private)
        .map_err(|e| oidc_core::OidcError::Internal(format!("invalid SAML realm key: {e}")))?
        .with_certificate(cert))
}

async fn idp_for(
    state: &OidcState,
    realm_name: &str,
    realm_id: uuid::Uuid,
    sp: &SamlServiceProvider,
) -> Result<IdentityProvider, oidc_core::OidcError> {
    let base = format!(
        "{}/realms/{realm_name}/protocol/saml",
        state.base_issuer.trim_end_matches('/')
    );
    IdentityProvider::new(IdentityProviderConfig {
        entity_id: format!("{base}/descriptor"),
        sso: vec![
            Endpoint::redirect(&base, 0, true),
            Endpoint::post(&base, 1, false),
        ],
        slo: vec![
            Endpoint::redirect(format!("{base}/logout"), 0, true),
            Endpoint::post(format!("{base}/logout"), 1, false),
        ],
        artifact_resolution: vec![],
        supported_name_id_formats: vec![
            NameIdFormat::Persistent,
            NameIdFormat::EmailAddress,
            NameIdFormat::Transient,
        ],
        default_name_id_format: NameIdFormat::Persistent,
        signing_key: realm_key(state, realm_id).await?,
        decryption_key: Some(realm_key(state, realm_id).await?),
        want_authn_requests_signed: sp.require_signed_requests,
        assertion_signing: IdpAssertionSigning {
            sign_responses: sp.sign_responses,
            sign_assertions: sp.sign_assertions,
        },
        encrypt_assertions_when_possible: sp.encrypt_assertions,
        logout_signing: IdpLogoutSigning {
            sign_requests: true,
            sign_responses: true,
        },
        logout_want_signed: IdpLogoutWantSigned {
            requests: true,
            responses: true,
        },
        default_session_duration: Duration::from_secs(3600),
        default_peer_crypto_policy: PeerCryptoPolicy::strong_defaults(),
        outbound_signature_algorithm: SignatureAlgorithm::RsaSha256,
        outbound_digest_algorithm: DigestAlgorithm::Sha256,
        outbound_c14n: C14nAlgorithm::ExclusiveCanonical,
        outbound_data_encryption_algorithm: DataEncryptionAlgorithm::Aes256Gcm,
        outbound_key_transport_algorithm: KeyTransportAlgorithm::RsaOaep,
    })
    .map_err(|e| oidc_core::OidcError::Internal(format!("invalid SAML IdP configuration: {e}")))
}

pub async fn idp_metadata(state: OidcState, realm_name: String) -> Response {
    let mut conn = match state.connect().await {
        Ok(c) => c,
        Err(e) => return saml_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };
    let realm = match RealmRepo.find_by_name(&mut conn, &realm_name).await {
        Ok(Some(r)) if r.enabled => r,
        Ok(_) => return saml_error(StatusCode::NOT_FOUND, "Realm not found"),
        Err(e) => return saml_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };
    // Metadata settings do not depend on a peer; require signed requests by default.
    let template = SamlServiceProvider {
        id: uuid::Uuid::nil(),
        realm_id: realm.id,
        name: String::new(),
        entity_id: String::new(),
        metadata_xml: String::new(),
        enabled: true,
        require_signed_requests: true,
        sign_responses: false,
        sign_assertions: true,
        encrypt_assertions: false,
        attribute_mapping: serde_json::json!({}),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        deleted_at: None,
    };
    match idp_for(&state, &realm_name, realm.id, &template)
        .await
        .and_then(|idp| {
            idp.metadata_xml(true)
                .map_err(|e| oidc_core::OidcError::Internal(e.to_string()))
        }) {
        Ok(xml) => (
            StatusCode::OK,
            [(
                axum::http::header::CONTENT_TYPE,
                "application/samlmetadata+xml",
            )],
            xml,
        )
            .into_response(),
        Err(e) => saml_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

pub async fn idp_sso(
    state: OidcState,
    realm_name: String,
    headers: HeaderMap,
    wire: String,
    binding: Binding,
    relay_state: Option<String>,
    resume: Option<String>,
) -> Response {
    let mut conn = match state.connect().await {
        Ok(c) => c,
        Err(e) => return saml_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };
    let realm = match RealmRepo.find_by_name(&mut conn, &realm_name).await {
        Ok(Some(r)) if r.enabled => r,
        Ok(_) => return saml_error(StatusCode::NOT_FOUND, "Realm not found"),
        Err(e) => return saml_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };
    let (wire, binding, relay_state, chosen, pending_id) = if let Some(token) = resume {
        let pending = match SamlRepo
            .find_pending(&mut conn, &token_hash(&token), "idp_sso")
            .await
        {
            Ok(Some(p)) => p,
            Ok(None) => {
                return saml_error(
                    StatusCode::BAD_REQUEST,
                    "This SAML request is expired or was already used",
                );
            }
            Err(e) => return saml_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
        };
        let Some(id) = pending.service_provider_id else {
            return saml_error(StatusCode::BAD_REQUEST, "Invalid SAML request");
        };
        let sp = match SamlRepo.find_service_provider(&mut conn, id).await {
            Ok(Some(s)) if s.enabled => s,
            _ => {
                return saml_error(
                    StatusCode::BAD_REQUEST,
                    "SAML service provider is unavailable",
                );
            }
        };
        (
            pending.wire_payload.unwrap_or_default(),
            if pending.binding.as_deref() == Some("post") {
                Binding::HttpPost
            } else {
                Binding::HttpRedirect
            },
            pending.relay_state,
            Some(sp),
            Some(pending.id),
        )
    } else {
        (wire, binding, relay_state, None, None)
    };
    let decoded = match decode_wire(wire.as_bytes(), binding, WireDirection::Request) {
        Ok(v) => v,
        Err(e) => {
            return saml_error(
                StatusCode::BAD_REQUEST,
                format!("Invalid SAML request: {e}"),
            );
        }
    };
    let expected = format!(
        "{}/realms/{realm_name}/protocol/saml",
        state.base_issuer.trim_end_matches('/')
    );
    let candidates = if let Some(sp) = chosen {
        vec![sp]
    } else {
        match SamlRepo.list_service_providers(&mut conn, realm.id).await {
            Ok(v) => v.into_iter().filter(|s| s.enabled).collect(),
            Err(e) => return saml_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
        }
    };
    let mut selected = None;
    for sp in candidates {
        let descriptor = match SpDescriptor::from_metadata_xml(sp.metadata_xml.as_bytes()) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let idp = match idp_for(&state, &realm_name, realm.id, &sp).await {
            Ok(v) => v,
            Err(_) => continue,
        };
        let parsed = idp.consume_authn_request(ConsumeAuthnRequest {
            sp: &descriptor,
            peer_crypto_policy: None,
            saml_request: &decoded.xml,
            binding,
            relay_state: relay_state.as_deref().or(decoded.relay_state.as_deref()),
            detached_signature: decoded.as_detached_signature(),
            expected_destination: &expected,
            now: SystemTime::now(),
            clock_skew: Duration::from_secs(60),
        });
        if let Ok(p) = parsed {
            selected = Some((sp, descriptor, idp, p));
            break;
        }
    }
    let Some((sp, descriptor, idp, parsed)) = selected else {
        return saml_error(
            StatusCode::BAD_REQUEST,
            "The SAML request is invalid, unsigned, or belongs to an unknown service provider",
        );
    };
    let user_session = match authenticated_user(&state, &headers, realm.id).await {
        Ok(v) => v,
        Err(e) => return saml_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };
    let Some((user, session)) = user_session else {
        let token = random_token();
        let now = Utc::now();
        let pending = SamlPendingRequest {
            id: uuid::Uuid::now_v7(),
            token_hash: token_hash(&token),
            realm_id: realm.id,
            service_provider_id: Some(sp.id),
            identity_provider_id: None,
            purpose: "idp_sso".into(),
            wire_payload: Some(wire),
            binding: Some(
                if binding == Binding::HttpPost {
                    "post"
                } else {
                    "redirect"
                }
                .into(),
            ),
            relay_state: relay_state.or(decoded.relay_state),
            tracker: None,
            return_to: None,
            expires_at: now + chrono::Duration::minutes(FLOW_TTL_MINUTES),
            used: false,
            created_at: now,
        };
        if let Err(e) = SamlRepo.create_pending(&mut conn, &pending).await {
            return saml_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string());
        }
        let back = format!(
            "/realms/{realm_name}/protocol/saml?flow={}",
            urlencoding::encode(&token)
        );
        let login = format!(
            "/realms/{realm_name}/login?return_to={}",
            urlencoding::encode(&back)
        );
        return (StatusCode::SEE_OTHER, [(LOCATION, login)]).into_response();
    };
    let request_replay_id = format!("request:{}", parsed.id);
    let replay_expiry = Utc::now() + chrono::Duration::minutes(FLOW_TTL_MINUTES);
    match SamlRepo
        .record_assertion(&mut conn, realm.id, &request_replay_id, replay_expiry)
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            return saml_error(
                StatusCode::BAD_REQUEST,
                "This SAML login request was already completed",
            );
        }
        Err(e) => return saml_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
    if let Some(id) = pending_id {
        match SamlRepo.mark_pending_used(&mut conn, id).await {
            Ok(true) => {}
            Ok(false) => {
                return saml_error(
                    StatusCode::BAD_REQUEST,
                    "This SAML request is expired or was already used",
                );
            }
            Err(e) => return saml_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
        }
    }
    let email_attribute = sp
        .attribute_mapping
        .get("email")
        .and_then(|v| v.as_str())
        .unwrap_or("email");
    let mut attributes = vec![Attribute::single(email_attribute, user.email.clone())];
    if let Some(v) = user.given_name.clone() {
        attributes.push(Attribute::single(
            sp.attribute_mapping
                .get("given_name")
                .and_then(|v| v.as_str())
                .unwrap_or("firstName"),
            v,
        ));
    }
    if let Some(v) = user.family_name.clone() {
        attributes.push(Attribute::single(
            sp.attribute_mapping
                .get("family_name")
                .and_then(|v| v.as_str())
                .unwrap_or("lastName"),
            v,
        ));
    }
    if let Some(obj) = user.attributes.as_object() {
        for (name, value) in obj {
            if let Some(s) = value.as_str() {
                attributes.push(Attribute::single(name, s));
            } else if let Some(a) = value.as_array() {
                attributes.push(Attribute::new(
                    name,
                    a.iter()
                        .filter_map(|v| v.as_str().map(str::to_owned))
                        .collect(),
                ));
            }
        }
    }
    let dispatch = match idp.issue_response(IssueResponse {
        sp: &descriptor,
        in_response_to: &parsed,
        name_id: NameId::persistent_for_sp(user.id.to_string(), &sp.entity_id),
        attributes,
        authn_instant: SystemTime::from(session.created_at),
        session_index: session.sid,
        session_not_on_or_after: Some(SystemTime::from(session.expires_at)),
        authn_context_class_ref: AuthnContextClassRef::PasswordProtectedTransport,
        force_encrypt_assertion: Some(sp.encrypt_assertions),
        now: SystemTime::now(),
        assertion_lifetime: Duration::from_secs(300),
        subject_confirmation_lifetime: Duration::from_secs(300),
        holder_of_key_cert: None,
    }) {
        Ok(v) => v,
        Err(e) => {
            return saml_error(
                StatusCode::BAD_REQUEST,
                format!("Could not issue SAML response: {e}"),
            );
        }
    };
    render_sso_dispatch(dispatch)
}

fn render_sso_dispatch(dispatch: saml::SsoResponseDispatch) -> Response {
    match dispatch {
        saml::SsoResponseDispatch::Post(form) => {
            let response = form.saml_response;
            let relay = form
                .relay_state
                .map(|v| {
                    format!(
                        "<input type=\"hidden\" name=\"RelayState\" value=\"{}\">",
                        html_escape(&v)
                    )
                })
                .unwrap_or_default();
            Html(format!("<!doctype html><title>Continue</title><form id=\"saml\" method=\"post\" action=\"{}\"><input type=\"hidden\" name=\"SAMLResponse\" value=\"{}\">{relay}<noscript><button type=\"submit\">Continue</button></noscript></form><script>document.getElementById('saml').submit()</script>",html_escape(form.action.as_str()),html_escape(&response))).into_response()
        }
        saml::SsoResponseDispatch::Artifact(a) => (
            StatusCode::SEE_OTHER,
            [(LOCATION, a.redirect_to.to_string())],
        )
            .into_response(),
    }
}

pub fn datetime_from_system(value: SystemTime) -> DateTime<Utc> {
    value.into()
}

async fn broker_sp(
    state: &OidcState,
    realm_name: &str,
    realm_id: uuid::Uuid,
    alias: &str,
) -> Result<ServiceProvider, oidc_core::OidcError> {
    let base = format!(
        "{}/realms/{realm_name}/protocol/saml/broker/{alias}",
        state.base_issuer.trim_end_matches('/')
    );
    let key = realm_key(state, realm_id).await?;
    ServiceProvider::new(ServiceProviderConfig {
        entity_id: format!("{base}/metadata"),
        acs: vec![SsoResponseEndpoint::post(
            format!("{base}/endpoint"),
            0,
            true,
        )],
        slo: vec![
            Endpoint::redirect(format!("{base}/logout"), 0, true),
            Endpoint::post(format!("{base}/logout"), 1, false),
        ],
        name_id_formats: vec![
            NameIdFormat::Persistent,
            NameIdFormat::EmailAddress,
            NameIdFormat::Transient,
        ],
        signing_key: Some(key.clone()),
        decryption_key: Some(key),
        sign_authn_requests: true,
        want_signed: SpWantSigned {
            response: false,
            assertions: true,
        },
        allow_unsolicited: false,
        logout_signing: SpLogoutSigning {
            sign_requests: true,
            sign_responses: true,
        },
        logout_want_signed: SpLogoutWantSigned {
            requests: true,
            responses: true,
        },
        default_peer_crypto_policy: PeerCryptoPolicy::strong_defaults(),
        outbound_signature_algorithm: SignatureAlgorithm::RsaSha256,
        outbound_digest_algorithm: DigestAlgorithm::Sha256,
    })
    .map_err(|e| oidc_core::OidcError::Internal(format!("invalid SAML broker configuration: {e}")))
}

async fn broker_context(
    state: &OidcState,
    realm_name: &str,
    alias: &str,
) -> Result<
    (
        oidc_core::models::Realm,
        BrokerProvider,
        IdpDescriptor,
        ServiceProvider,
    ),
    oidc_core::OidcError,
> {
    let mut conn = state.connect().await?;
    let realm = RealmRepo
        .find_by_name(&mut conn, realm_name)
        .await?
        .filter(|r| r.enabled)
        .ok_or_else(|| oidc_core::OidcError::NotFound("realm".into()))?;
    let provider = IdentityProviderRepo
        .find_by_alias(&mut conn, realm.id, alias)
        .await?
        .filter(|p| p.enabled && p.provider_type == oidc_core::models::IdentityProviderType::Saml)
        .ok_or_else(|| oidc_core::OidcError::NotFound("SAML identity provider".into()))?;
    let metadata = provider.saml_metadata_xml.as_deref().ok_or_else(|| {
        oidc_core::OidcError::InvalidInput("SAML identity provider metadata is missing".into())
    })?;
    let idp = IdpDescriptor::from_metadata_xml(metadata.as_bytes()).map_err(|e| {
        oidc_core::OidcError::InvalidInput(format!("invalid SAML identity provider metadata: {e}"))
    })?;
    let sp = broker_sp(state, realm_name, realm.id, alias).await?;
    Ok((realm, provider, idp, sp))
}

pub async fn broker_metadata(state: OidcState, realm_name: String, alias: String) -> Response {
    match broker_context(&state, &realm_name, &alias)
        .await
        .and_then(|(_, _, _, sp)| {
            sp.metadata_xml(true)
                .map_err(|e| oidc_core::OidcError::Internal(e.to_string()))
        }) {
        Ok(xml) => (
            StatusCode::OK,
            [(
                axum::http::header::CONTENT_TYPE,
                "application/samlmetadata+xml",
            )],
            xml,
        )
            .into_response(),
        Err(e) => saml_error(StatusCode::BAD_REQUEST, e.to_string()),
    }
}

pub async fn broker_start(
    state: OidcState,
    realm_name: String,
    alias: String,
    return_to: String,
) -> Response {
    let (realm, provider, idp, sp) = match broker_context(&state, &realm_name, &alias).await {
        Ok(v) => v,
        Err(e) => return saml_error(StatusCode::BAD_REQUEST, e.to_string()),
    };
    let absolute = match url::Url::parse(&return_to)
        .or_else(|_| url::Url::parse(&state.base_issuer).and_then(|b| b.join(&return_to)))
    {
        Ok(v) => v,
        Err(_) => return saml_error(StatusCode::BAD_REQUEST, "Invalid return URL"),
    };
    if absolute.origin()
        != url::Url::parse(&state.base_issuer)
            .map(|u| u.origin())
            .unwrap_or_else(|_| absolute.origin())
    {
        return saml_error(
            StatusCode::BAD_REQUEST,
            "Return URL must belong to this server",
        );
    }
    let client_id = absolute
        .query_pairs()
        .find(|(k, _)| k == "client_id")
        .map(|(_, v)| v.into_owned());
    let mut conn = match state.connect().await {
        Ok(v) => v,
        Err(e) => return saml_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };
    if let Some(ref id) = client_id {
        match ClientRepo
            .find_by_client_id_in_realm(&mut conn, id, realm.id)
            .await
        {
            Ok(Some(c)) if c.enabled => {}
            _ => return saml_error(StatusCode::BAD_REQUEST, "Unknown local client"),
        }
    } else {
        return saml_error(
            StatusCode::BAD_REQUEST,
            "The authorization request has no client_id",
        );
    }
    let token = random_token();
    let start = match sp.start_login(
        &idp,
        StartLogin {
            relay_state: Some(&token),
            binding: Binding::HttpRedirect,
            force_authn: false,
            is_passive: false,
            requested_name_id_format: Some(NameIdFormat::Persistent),
            requested_authn_context: None,
            acs_index: None,
            acs_url: None,
            response_binding: Some(SsoResponseBinding::HttpPost),
        },
    ) {
        Ok(v) => v,
        Err(e) => {
            return saml_error(
                StatusCode::BAD_REQUEST,
                format!("Could not start SAML login: {e}"),
            );
        }
    };
    let now = Utc::now();
    let pending = SamlPendingRequest {
        id: uuid::Uuid::now_v7(),
        token_hash: token_hash(&token),
        realm_id: realm.id,
        service_provider_id: None,
        identity_provider_id: Some(provider.id),
        purpose: "broker_login".into(),
        wire_payload: None,
        binding: Some("post".into()),
        relay_state: Some(token),
        tracker: serde_json::to_value(&start.tracker).ok(),
        return_to: Some(absolute.to_string()),
        expires_at: now + chrono::Duration::minutes(FLOW_TTL_MINUTES),
        used: false,
        created_at: now,
    };
    if let Err(e) = SamlRepo.create_pending(&mut conn, &pending).await {
        return saml_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string());
    }
    render_dispatch(start.dispatch)
}

fn render_dispatch(dispatch: Dispatch) -> Response {
    match dispatch {
        Dispatch::Redirect(url) => {
            (StatusCode::SEE_OTHER, [(LOCATION, url.to_string())]).into_response()
        }
        Dispatch::Post(form) => {
            let (message_name, message) = if let Some(request) = form.saml_request {
                ("SAMLRequest", request)
            } else {
                ("SAMLResponse", form.saml_response.unwrap_or_default())
            };
            let relay = form
                .relay_state
                .map(|v| {
                    format!(
                        "<input type=\"hidden\" name=\"RelayState\" value=\"{}\">",
                        html_escape(&v)
                    )
                })
                .unwrap_or_default();
            Html(format!("<!doctype html><title>Continue</title><form id=\"saml\" method=\"post\" action=\"{}\"><input type=\"hidden\" name=\"{}\" value=\"{}\">{relay}<noscript><button type=\"submit\">Continue</button></noscript></form><script>document.getElementById('saml').submit()</script>",html_escape(form.action.as_str()),message_name,html_escape(&message))).into_response()
        }
    }
}

fn attribute_value(identity: &saml::Identity, name: &str) -> Option<String> {
    identity
        .attributes
        .iter()
        .find(|a| a.name == name || a.friendly_name.as_deref() == Some(name))
        .and_then(|a| a.values.first())
        .cloned()
}

pub async fn broker_acs(
    state: OidcState,
    realm_name: String,
    alias: String,
    saml_response: String,
    relay_state: String,
) -> Response {
    let (realm, provider, idp, sp) = match broker_context(&state, &realm_name, &alias).await {
        Ok(v) => v,
        Err(e) => return saml_error(StatusCode::BAD_REQUEST, e.to_string()),
    };
    let mut conn = match state.connect().await {
        Ok(v) => v,
        Err(e) => return saml_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };
    let pending = match SamlRepo
        .find_pending(&mut conn, &token_hash(&relay_state), "broker_login")
        .await
    {
        Ok(Some(v)) if v.realm_id == realm.id && v.identity_provider_id == Some(provider.id) => v,
        _ => {
            return saml_error(
                StatusCode::BAD_REQUEST,
                "This SAML login is expired or was already used",
            );
        }
    };
    let tracker: LoginTracker = match pending
        .tracker
        .clone()
        .and_then(|v| serde_json::from_value(v).ok())
    {
        Some(v) => v,
        None => return saml_error(StatusCode::BAD_REQUEST, "Invalid SAML request state"),
    };
    let decoded = match decode_wire(
        saml_response.as_bytes(),
        Binding::HttpPost,
        WireDirection::Response,
    ) {
        Ok(v) => v,
        Err(e) => {
            return saml_error(
                StatusCode::BAD_REQUEST,
                format!("Invalid SAML response: {e}"),
            );
        }
    };
    let acs = format!(
        "{}/realms/{realm_name}/protocol/saml/broker/{alias}/endpoint",
        state.base_issuer.trim_end_matches('/')
    );
    let identity = match sp.consume_response(ConsumeResponse {
        idp: &idp,
        peer_crypto_policy: None,
        saml_response: &decoded.xml,
        binding: SsoResponseBinding::HttpPost,
        relay_state: Some(&relay_state),
        tracker: Some(&tracker),
        expected_destination: &acs,
        now: SystemTime::now(),
        clock_skew: Duration::from_secs(60),
        replay_cache: None,
        replay_mode: ReplayMode::All,
        holder_of_key_cert: None,
    }) {
        Ok(v) => v,
        Err(e) => {
            return saml_error(
                StatusCode::BAD_REQUEST,
                format!("SAML response validation failed: {e}"),
            );
        }
    };
    let expiry = datetime_from_system(identity.not_on_or_after);
    match SamlRepo
        .record_assertion(&mut conn, realm.id, &identity.assertion_id, expiry)
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            return saml_error(StatusCode::CONFLICT, "This SAML assertion was already used");
        }
        Err(e) => return saml_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
    if !matches!(
        SamlRepo.mark_pending_used(&mut conn, pending.id).await,
        Ok(true)
    ) {
        return saml_error(
            StatusCode::CONFLICT,
            "This SAML login was already completed",
        );
    }
    let mapping = &provider.saml_attribute_mapping;
    let email_name = mapping
        .get("email")
        .and_then(|v| v.as_str())
        .unwrap_or("email");
    let given_name = mapping
        .get("given_name")
        .and_then(|v| v.as_str())
        .unwrap_or("firstName");
    let family_name = mapping
        .get("family_name")
        .and_then(|v| v.as_str())
        .unwrap_or("lastName");
    let email = attribute_value(&identity, email_name).or_else(|| {
        if identity.name_id.value.contains('@') {
            Some(identity.name_id.value.clone())
        } else {
            None
        }
    });
    let given = attribute_value(&identity, given_name);
    let family = attribute_value(&identity, family_name);
    let display = given.as_deref().or(family.as_deref());
    let (mut user, _) = match super::social_login::find_or_create_local_user(
        &mut conn,
        &provider,
        &identity.name_id.value,
        email.as_deref(),
        display,
        realm.id,
    )
    .await
    {
        Ok(v) => v,
        Err(e) => return saml_error(StatusCode::FORBIDDEN, e.to_string()),
    };
    if user.given_name.is_none() {
        user.given_name = given
    }
    if user.family_name.is_none() {
        user.family_name = family
    }
    let _ = UserRepo.update(&mut conn, &user).await;
    let return_to = pending.return_to.unwrap_or_else(|| "/".into());
    let parsed = url::Url::parse(&return_to).ok();
    let client_string = parsed
        .as_ref()
        .and_then(|u| {
            u.query_pairs()
                .find(|(k, _)| k == "client_id")
                .map(|(_, v)| v.into_owned())
        })
        .unwrap_or_default();
    let client = match ClientRepo
        .find_by_client_id_in_realm(&mut conn, &client_string, realm.id)
        .await
    {
        Ok(Some(v)) => v,
        _ => return saml_error(StatusCode::BAD_REQUEST, "Unknown local client"),
    };
    let now = Utc::now();
    let upstream_session_index = identity.session_index.clone();
    let session = Session {
        id: uuid::Uuid::now_v7(),
        sid: upstream_session_index
            .map(|v| format!("saml:{}:{v}", provider.id))
            .unwrap_or_else(|| uuid::Uuid::now_v7().to_string()),
        user_id: Some(user.id),
        realm_id: realm.id,
        client_id: client.id,
        grant_type: "saml".into(),
        access_token_hash: token_hash(&random_token()),
        refresh_token_hash: None,
        id_token_jti: None,
        scope: vec![],
        revoked: false,
        expires_at: now + chrono::Duration::hours(8),
        refresh_expires_at: None,
        offline_session: false,
        offline_max_expires_at: None,
        created_at: now,
        last_used_at: None,
        token_family_id: None,
        previous_session_id: None,
        rotated_at: None,
        reused_at: None,
        family_revoked: false,
        authorization_details: None,
        resource: vec![],
        acr: identity
            .authn_context_class_ref
            .unwrap_or_else(|| "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified".into()),
        amr: vec!["federated".into(), "saml".into()],
    };
    if let Err(e) = SessionRepo.create(&mut conn, &session).await {
        return saml_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string());
    }
    let key = match state.decode_encryption_key() {
        Ok(v) => v,
        Err(e) => return saml_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };
    let mut response = (StatusCode::SEE_OTHER, [(LOCATION, return_to)]).into_response();
    session_cookie::append_set_cookie(
        response.headers_mut(),
        session_cookie::session_cookie_header(&session.id.to_string(), &key),
    );
    response
}

pub async fn idp_logout(
    state: OidcState,
    realm_name: String,
    wire: String,
    binding: Binding,
    relay_state: Option<String>,
) -> Response {
    let mut conn = match state.connect().await {
        Ok(v) => v,
        Err(e) => return saml_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };
    let realm = match RealmRepo.find_by_name(&mut conn, &realm_name).await {
        Ok(Some(v)) if v.enabled => v,
        _ => return saml_error(StatusCode::NOT_FOUND, "Realm not found"),
    };
    let decoded = match decode_wire(wire.as_bytes(), binding, WireDirection::Request) {
        Ok(v) => v,
        Err(e) => {
            return saml_error(
                StatusCode::BAD_REQUEST,
                format!("Invalid logout request: {e}"),
            );
        }
    };
    let expected = format!(
        "{}/realms/{realm_name}/protocol/saml/logout",
        state.base_issuer.trim_end_matches('/')
    );
    let peers = match SamlRepo.list_service_providers(&mut conn, realm.id).await {
        Ok(v) => v,
        Err(e) => return saml_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };
    let mut accepted = None;
    for client in peers.into_iter().filter(|v| v.enabled) {
        let descriptor = match SpDescriptor::from_metadata_xml(client.metadata_xml.as_bytes()) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let idp = match idp_for(&state, &realm_name, realm.id, &client).await {
            Ok(v) => v,
            Err(_) => continue,
        };
        if let Ok(parsed) = idp.consume_logout_request(
            &descriptor,
            ConsumeLogoutRequest {
                peer_crypto_policy: None,
                body: &decoded.xml,
                binding,
                detached_signature: decoded.as_detached_signature(),
                expected_destination: &expected,
                now: SystemTime::now(),
                clock_skew: Duration::from_secs(60),
            },
        ) {
            accepted = Some((idp, descriptor, parsed));
            break;
        }
    }
    let Some((idp, descriptor, parsed)) = accepted else {
        return saml_error(
            StatusCode::BAD_REQUEST,
            "The logout request is invalid or unsigned",
        );
    };
    for sid in &parsed.session_index {
        if let Ok(Some(session)) = SessionRepo.find_by_sid(&mut conn, sid).await {
            if session.realm_id == realm.id {
                let _ = SessionRepo.revoke(&mut conn, session.id).await;
            }
        }
    }
    let dispatch = match idp.build_logout_response(
        &descriptor,
        &parsed,
        LogoutStatus::Success,
        relay_state.as_deref().or(decoded.relay_state.as_deref()),
        binding,
    ) {
        Ok(v) => v,
        Err(e) => {
            return saml_error(
                StatusCode::BAD_REQUEST,
                format!("Could not build logout response: {e}"),
            );
        }
    };
    let mut response = render_dispatch(dispatch);
    session_cookie::append_set_cookie(
        response.headers_mut(),
        session_cookie::clear_session_cookie_header(),
    );
    response
}

pub async fn broker_logout(
    state: OidcState,
    realm_name: String,
    alias: String,
    wire: String,
    binding: Binding,
) -> Response {
    let (realm, provider, idp, sp) = match broker_context(&state, &realm_name, &alias).await {
        Ok(v) => v,
        Err(e) => return saml_error(StatusCode::BAD_REQUEST, e.to_string()),
    };
    let endpoint = format!(
        "{}/realms/{realm_name}/protocol/saml/broker/{alias}/logout",
        state.base_issuer.trim_end_matches('/')
    );
    let parsed = match sp.consume_logout_request(
        &idp,
        ConsumeLogoutRequest {
            peer_crypto_policy: None,
            body: wire.as_bytes(),
            binding,
            detached_signature: None,
            expected_destination: &endpoint,
            now: SystemTime::now(),
            clock_skew: Duration::from_secs(60),
        },
    ) {
        Ok(v) => v,
        Err(e) => {
            return saml_error(
                StatusCode::BAD_REQUEST,
                format!("SAML logout validation failed: {e}"),
            );
        }
    };
    let mut conn = match state.connect().await {
        Ok(v) => v,
        Err(e) => return saml_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };
    for upstream in &parsed.session_index {
        let sid = format!("saml:{}:{upstream}", provider.id);
        if let Ok(Some(session)) = SessionRepo.find_by_sid(&mut conn, &sid).await {
            if session.realm_id == realm.id {
                let _ = SessionRepo.revoke(&mut conn, session.id).await;
            }
        }
    }
    let dispatch = match sp.build_logout_response(
        &idp,
        &parsed,
        LogoutStatus::Success,
        parsed.relay_state.as_deref(),
        binding,
    ) {
        Ok(v) => v,
        Err(e) => return saml_error(StatusCode::BAD_REQUEST, e.to_string()),
    };
    let mut response = render_dispatch(dispatch);
    session_cookie::append_set_cookie(
        response.headers_mut(),
        session_cookie::clear_session_cookie_header(),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> KeyPair {
        let rsa = rsa::RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
        let pem = rsa
            .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
            .unwrap()
            .to_string();
        let cert_key = rcgen::KeyPair::from_pem(&pem).unwrap();
        let cert = rcgen::CertificateParams::new(vec!["SAML test".into()])
            .unwrap()
            .self_signed(&cert_key)
            .unwrap();
        KeyPair::from_pkcs8_pem(pem.as_bytes())
            .unwrap()
            .with_certificate(saml::X509Certificate::from_pem(cert.pem().as_bytes()).unwrap())
    }

    #[test]
    fn signed_encrypted_browser_sso_round_trip() {
        let sp_url = "https://app.example.test/saml";
        let acs = "https://app.example.test/saml/acs";
        let idp_url = "https://login.example.test/realms/acme/protocol/saml";
        let sp_key = key();
        let sp = ServiceProvider::new(ServiceProviderConfig {
            entity_id: sp_url.into(),
            acs: vec![SsoResponseEndpoint::post(acs, 0, true)],
            slo: vec![Endpoint::redirect(
                "https://app.example.test/saml/logout",
                0,
                true,
            )],
            name_id_formats: vec![NameIdFormat::Persistent, NameIdFormat::EmailAddress],
            signing_key: Some(sp_key.clone()),
            decryption_key: Some(sp_key),
            sign_authn_requests: true,
            want_signed: SpWantSigned {
                response: false,
                assertions: true,
            },
            allow_unsolicited: false,
            logout_signing: SpLogoutSigning {
                sign_requests: true,
                sign_responses: true,
            },
            logout_want_signed: SpLogoutWantSigned {
                requests: true,
                responses: true,
            },
            default_peer_crypto_policy: PeerCryptoPolicy::strong_defaults(),
            outbound_signature_algorithm: SignatureAlgorithm::RsaSha256,
            outbound_digest_algorithm: DigestAlgorithm::Sha256,
        })
        .unwrap();
        let idp = IdentityProvider::new(IdentityProviderConfig {
            entity_id: format!("{idp_url}/descriptor"),
            sso: vec![
                Endpoint::redirect(idp_url, 0, true),
                Endpoint::post(idp_url, 1, false),
            ],
            slo: vec![Endpoint::redirect(format!("{idp_url}/logout"), 0, true)],
            artifact_resolution: vec![],
            supported_name_id_formats: vec![NameIdFormat::Persistent, NameIdFormat::EmailAddress],
            default_name_id_format: NameIdFormat::Persistent,
            signing_key: key(),
            decryption_key: None,
            want_authn_requests_signed: true,
            assertion_signing: IdpAssertionSigning {
                sign_responses: false,
                sign_assertions: true,
            },
            encrypt_assertions_when_possible: true,
            logout_signing: IdpLogoutSigning {
                sign_requests: true,
                sign_responses: true,
            },
            logout_want_signed: IdpLogoutWantSigned {
                requests: true,
                responses: true,
            },
            default_session_duration: Duration::from_secs(3600),
            default_peer_crypto_policy: PeerCryptoPolicy::strong_defaults(),
            outbound_signature_algorithm: SignatureAlgorithm::RsaSha256,
            outbound_digest_algorithm: DigestAlgorithm::Sha256,
            outbound_c14n: C14nAlgorithm::ExclusiveCanonical,
            outbound_data_encryption_algorithm: DataEncryptionAlgorithm::Aes256Gcm,
            outbound_key_transport_algorithm: KeyTransportAlgorithm::RsaOaep,
        })
        .unwrap();
        let sp_descriptor =
            SpDescriptor::from_metadata_xml(sp.metadata_xml(true).unwrap().as_bytes()).unwrap();
        let idp_descriptor =
            IdpDescriptor::from_metadata_xml(idp.metadata_xml(true).unwrap().as_bytes()).unwrap();
        let started = sp
            .start_login(
                &idp_descriptor,
                StartLogin {
                    relay_state: Some("return-state"),
                    binding: Binding::HttpRedirect,
                    force_authn: false,
                    is_passive: false,
                    requested_name_id_format: Some(NameIdFormat::Persistent),
                    requested_authn_context: None,
                    acs_index: None,
                    acs_url: None,
                    response_binding: Some(SsoResponseBinding::HttpPost),
                },
            )
            .unwrap();
        let request_url = match &started.dispatch {
            Dispatch::Redirect(v) => v,
            _ => panic!("redirect expected"),
        };
        let decoded = decode_wire(
            request_url.query().unwrap().as_bytes(),
            Binding::HttpRedirect,
            WireDirection::Request,
        )
        .unwrap();
        let parsed = idp
            .consume_authn_request(ConsumeAuthnRequest {
                sp: &sp_descriptor,
                peer_crypto_policy: None,
                saml_request: &decoded.xml,
                binding: Binding::HttpRedirect,
                relay_state: decoded.relay_state.as_deref(),
                detached_signature: decoded.as_detached_signature(),
                expected_destination: idp_url,
                now: SystemTime::now(),
                clock_skew: Duration::from_secs(60),
            })
            .unwrap();
        let response = idp
            .issue_response(IssueResponse {
                sp: &sp_descriptor,
                in_response_to: &parsed,
                name_id: NameId::persistent_for_sp("user-123", sp_url),
                attributes: vec![
                    Attribute::email("alice@example.test"),
                    Attribute::single("groups", "engineering"),
                ],
                authn_instant: SystemTime::now(),
                session_index: "session-123".into(),
                session_not_on_or_after: Some(SystemTime::now() + Duration::from_secs(3600)),
                authn_context_class_ref: AuthnContextClassRef::PasswordProtectedTransport,
                force_encrypt_assertion: Some(true),
                now: SystemTime::now(),
                assertion_lifetime: Duration::from_secs(300),
                subject_confirmation_lifetime: Duration::from_secs(300),
                holder_of_key_cert: None,
            })
            .unwrap();
        let form = match response {
            saml::SsoResponseDispatch::Post(v) => v,
            _ => panic!("post expected"),
        };
        let decoded = decode_wire(
            form.saml_response.as_bytes(),
            Binding::HttpPost,
            WireDirection::Response,
        )
        .unwrap();
        let identity = sp
            .consume_response(ConsumeResponse {
                idp: &idp_descriptor,
                peer_crypto_policy: None,
                saml_response: &decoded.xml,
                binding: SsoResponseBinding::HttpPost,
                relay_state: form.relay_state.as_deref(),
                tracker: Some(&started.tracker),
                expected_destination: acs,
                now: SystemTime::now(),
                clock_skew: Duration::from_secs(60),
                replay_cache: None,
                replay_mode: ReplayMode::All,
                holder_of_key_cert: None,
            })
            .unwrap();
        assert_eq!(identity.name_id.value, "user-123");
        assert!(
            identity
                .attributes
                .iter()
                .any(|a| a.values.iter().any(|v| v == "alice@example.test"))
        );
    }
}
