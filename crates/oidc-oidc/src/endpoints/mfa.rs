use axum::{
    Json,
    http::{HeaderMap, header::AUTHORIZATION},
};
use chrono::{Duration, Utc};
use hmac::{Hmac, Mac};
use oidc_core::{
    OidcError,
    models::{MfaCeremony, RecoveryCode, TotpCredential, User, WebauthnCredential},
    traits::hasher::{Argon2idHasher, Hasher},
    utils::{generate_opaque_token, generate_uuid_v7, sha2_256_hex},
};
use oidc_repository::{
    Connection,
    repositories::{mfa_repo::MfaRepo, session_repo::SessionRepo, user_repo::UserRepo},
};
use passkey_auth::{
    Attachment, AuthenticationResponse, AuthenticationState, PasskeyCredential,
    RegistrationResponse, RegistrationState, Webauthn,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha1::Sha1;
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::state::OidcState;

const CEREMONY_MINUTES: i64 = 5;
const MAX_ATTEMPTS: i32 = 5;
const RECOVERY_CODE_COUNT: usize = 10;

#[derive(Debug, Deserialize)]
pub struct TotpFinishRequest {
    pub ceremony_token: String,
    pub code: String,
    pub label: Option<String>,
}
#[derive(Debug, Deserialize)]
pub struct WebauthnFinishRequest {
    pub ceremony_token: String,
    pub label: Option<String>,
    pub response: RegistrationResponse,
}
#[derive(Debug, Deserialize)]
pub struct DeleteCredentialRequest {
    pub credential_id: Option<Uuid>,
}

#[derive(Debug, Deserialize)]
pub struct LoginMfaProof {
    pub ceremony_token: String,
    pub totp_code: Option<String>,
    pub recovery_code: Option<String>,
    pub webauthn_response: Option<AuthenticationResponse>,
}

#[derive(Debug, Serialize)]
pub struct LoginMfaChallenge {
    pub ceremony_token: String,
    pub methods: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webauthn: Option<Value>,
    pub expires_in: i64,
}

pub struct VerifiedMfa {
    pub amr: Vec<String>,
}

fn webauthn(state: &OidcState) -> Result<Webauthn, OidcError> {
    let parsed = url::Url::parse(&state.issuer)
        .map_err(|_| OidcError::Internal("issuer is not a valid WebAuthn origin".into()))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| OidcError::Internal("issuer has no host".into()))?;
    let mut origin = format!("{}://{}", parsed.scheme(), host);
    if let Some(port) = parsed.port() {
        origin.push_str(&format!(":{port}"));
    }
    Ok(Webauthn::new(host, "OpenID Connect Hub", &origin)
        .authenticator_attachment(Attachment::Any)
        .require_user_verification(true)
        .strict_base64(true))
}

fn base32(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let (mut buffer, mut bits) = (0u32, 0u8);
    let mut out = String::new();
    for &b in bytes {
        buffer = (buffer << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buffer >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buffer << (5 - bits)) & 31) as usize] as char);
    }
    out
}

fn totp_at(secret: &[u8], step: i64) -> String {
    let mut mac = Hmac::<Sha1>::new_from_slice(secret).expect("HMAC accepts arbitrary key lengths");
    mac.update(&(step as u64).to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = (digest[19] & 0x0f) as usize;
    let binary = (u32::from(digest[offset] & 0x7f) << 24)
        | (u32::from(digest[offset + 1]) << 16)
        | (u32::from(digest[offset + 2]) << 8)
        | u32::from(digest[offset + 3]);
    format!("{:06}", binary % 1_000_000)
}

fn verify_totp(secret: &[u8], code: &str, now: i64) -> bool {
    if code.len() != 6 || !code.bytes().all(|c| c.is_ascii_digit()) {
        return false;
    }
    (-1..=1).any(|window| {
        totp_at(secret, now / 30 + window)
            .as_bytes()
            .ct_eq(code.as_bytes())
            .into()
    })
}

fn matching_totp_step(secret: &[u8], code: &str, now: i64) -> Option<i64> {
    if code.len() != 6 || !code.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    (-1..=1).map(|window| now / 30 + window).find(|step| {
        totp_at(secret, *step)
            .as_bytes()
            .ct_eq(code.as_bytes())
            .into()
    })
}

fn valid_ceremony(c: &MfaCeremony, user_id: Uuid, purpose: &str) -> Result<(), OidcError> {
    if c.user_id != user_id
        || c.purpose != purpose
        || c.used_at.is_some()
        || c.expires_at <= Utc::now()
        || c.attempts >= MAX_ATTEMPTS
    {
        return Err(OidcError::AuthenticationFailed(
            "MFA challenge is invalid or expired".into(),
        ));
    }
    Ok(())
}

async fn current_user(state: &OidcState, headers: &HeaderMap) -> Result<User, OidcError> {
    let mut conn = state.connect().await?;
    if let Some(raw) = headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
    {
        state
            .verify_access_token_with_claims_any_issuer(raw)
            .await?;
        if let Some(session) = SessionRepo
            .find_by_access_token_hash(&mut conn, &sha2_256_hex(raw))
            .await?
        {
            if let Some(user_id) = session.user_id {
                if let Some(user) = UserRepo.find_by_id(&mut conn, user_id).await? {
                    return Ok(user);
                }
            }
        }
    }
    Err(OidcError::AuthenticationFailed(
        "Authentication required".into(),
    ))
}

async fn enrollment_user(state: &OidcState, headers: &HeaderMap) -> Result<User, OidcError> {
    if let Ok(user) = current_user(state, headers).await {
        return Ok(user);
    }
    let raw = headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| OidcError::AuthenticationFailed("Authentication required".into()))?;
    let (_, user, realm) = crate::endpoints::required_actions::action_user(state, raw).await?;
    let mut conn = state.connect().await?;
    let pending =
        crate::endpoints::required_actions::pending_actions(&mut conn, &user, &realm).await?;
    if !pending.contains(&oidc_core::models::RequiredActionKind::ConfigureMfa) {
        return Err(OidcError::AuthorizationDenied(
            "MFA enrollment is not required".into(),
        ));
    }
    Ok(user)
}

async fn current_mfa_user(state: &OidcState, headers: &HeaderMap) -> Result<User, OidcError> {
    let raw = headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| OidcError::AuthenticationFailed("Authentication required".into()))?;
    state
        .verify_access_token_with_claims_any_issuer(raw)
        .await?;
    let mut conn = state.connect().await?;
    let session = SessionRepo
        .find_by_access_token_hash(&mut conn, &sha2_256_hex(raw))
        .await?
        .ok_or_else(|| OidcError::AuthenticationFailed("Active session required".into()))?;
    if session.acr != oidc_core::utils::ACR_SILVER
        || !session.amr.iter().any(|v| v == oidc_core::utils::AMR_MFA)
    {
        return Err(OidcError::AuthorizationDenied(
            "Complete MFA again before changing recovery methods".into(),
        ));
    }
    let user_id = session
        .user_id
        .ok_or_else(|| OidcError::AuthenticationFailed("User session required".into()))?;
    UserRepo
        .find_by_id(&mut conn, user_id)
        .await?
        .ok_or_else(|| OidcError::AuthenticationFailed("User not found".into()))
}

fn recovery_plaintext() -> Result<String, OidcError> {
    let mut raw = [0u8; 8];
    getrandom::fill(&mut raw).map_err(|e| OidcError::Internal(e.to_string()))?;
    let s = hex::encode(raw).to_uppercase();
    Ok(format!(
        "{}-{}-{}-{}",
        &s[0..4],
        &s[4..8],
        &s[8..12],
        &s[12..16]
    ))
}

async fn replace_recovery(conn: &mut Connection, user_id: Uuid) -> Result<Vec<String>, OidcError> {
    let hasher = Argon2idHasher::new();
    let mut plain = Vec::with_capacity(RECOVERY_CODE_COUNT);
    let mut stored = Vec::with_capacity(RECOVERY_CODE_COUNT);
    for _ in 0..RECOVERY_CODE_COUNT {
        let code = recovery_plaintext()?;
        let hash = hasher.hash(&code)?;
        stored.push(RecoveryCode {
            id: generate_uuid_v7(),
            user_id,
            code_hash: hash,
            used_at: None,
        });
        plain.push(code);
    }
    MfaRepo
        .replace_recovery_codes(conn, user_id, &stored)
        .await?;
    Ok(plain)
}

pub async fn status_handler(
    state: OidcState,
    headers: HeaderMap,
) -> Result<Json<Value>, OidcError> {
    let user = current_user(&state, &headers).await?;
    let mut conn = state.connect().await?;
    let totp = MfaRepo.find_totp(&mut conn, user.id).await?;
    let passkeys = MfaRepo.list_webauthn(&mut conn, user.id).await?;
    let recovery = MfaRepo.recovery_code_count(&mut conn, user.id).await?;
    Ok(Json(
        json!({"totp":totp.map(|v|json!({"id":v.id,"label":v.label,"created_at":v.created_at,"last_used_at":v.last_used_at})),"passkeys":passkeys,"recovery_codes_remaining":recovery}),
    ))
}

pub async fn totp_start_handler(
    state: OidcState,
    headers: HeaderMap,
) -> Result<Json<Value>, OidcError> {
    let user = enrollment_user(&state, &headers).await?;
    let mut secret = [0u8; 20];
    getrandom::fill(&mut secret).map_err(|e| OidcError::Internal(e.to_string()))?;
    let shown = base32(&secret);
    let token = generate_opaque_token()?;
    let encrypted = state.encrypt_sensitive_value(&secret)?;
    let now = Utc::now();
    let ceremony = MfaCeremony {
        id: generate_uuid_v7(),
        token_hash: sha2_256_hex(&token),
        user_id: user.id,
        realm_id: user.realm_id,
        client_id: None,
        purpose: "totp_enrollment".into(),
        state: json!({"secret":encrypted}),
        attempts: 0,
        expires_at: now + Duration::minutes(CEREMONY_MINUTES),
        used_at: None,
        created_at: now,
    };
    let mut conn = state.connect().await?;
    MfaRepo.create_ceremony(&mut conn, &ceremony).await?;
    let issuer = url::form_urlencoded::byte_serialize(b"OpenID Connect Hub").collect::<String>();
    let account = url::form_urlencoded::byte_serialize(user.email.as_bytes()).collect::<String>();
    let uri = format!(
        "otpauth://totp/{issuer}:{account}?secret={shown}&issuer={issuer}&algorithm=SHA1&digits=6&period=30"
    );
    Ok(Json(
        json!({"ceremony_token":token,"secret":shown,"otpauth_uri":uri,"expires_in":CEREMONY_MINUTES*60}),
    ))
}

pub async fn totp_finish_handler(
    state: OidcState,
    headers: HeaderMap,
    req: TotpFinishRequest,
) -> Result<Json<Value>, OidcError> {
    let user = enrollment_user(&state, &headers).await?;
    let mut conn = state.connect().await?;
    let hash = sha2_256_hex(&req.ceremony_token);
    let c = MfaRepo
        .find_ceremony_for_update(&mut conn, &hash)
        .await?
        .ok_or_else(|| {
            OidcError::AuthenticationFailed("MFA challenge is invalid or expired".into())
        })?;
    valid_ceremony(&c, user.id, "totp_enrollment")?;
    let encrypted = c
        .state
        .get("secret")
        .and_then(Value::as_str)
        .ok_or_else(|| OidcError::Internal("TOTP enrollment state is incomplete".into()))?;
    let secret = state.decrypt_sensitive_value(encrypted)?;
    if !verify_totp(&secret, req.code.trim(), Utc::now().timestamp()) {
        MfaRepo.fail_ceremony(&mut conn, c.id).await?;
        return Err(OidcError::AuthenticationFailed(
            "Invalid authenticator code".into(),
        ));
    }
    let value = TotpCredential {
        id: generate_uuid_v7(),
        user_id: user.id,
        secret_encrypted: encrypted.into(),
        label: req.label.unwrap_or_else(|| "Authenticator app".into()),
        created_at: Utc::now(),
        last_used_at: None,
    };
    MfaRepo.save_totp(&mut conn, &value).await?;
    MfaRepo.use_ceremony(&mut conn, c.id).await?;
    let codes = replace_recovery(&mut conn, user.id).await?;
    Ok(Json(json!({"enabled":true,"recovery_codes":codes})))
}

pub async fn webauthn_start_handler(
    state: OidcState,
    headers: HeaderMap,
) -> Result<Json<Value>, OidcError> {
    let user = enrollment_user(&state, &headers).await?;
    let mut conn = state.connect().await?;
    let existing = MfaRepo.list_webauthn(&mut conn, user.id).await?;
    let credentials: Vec<PasskeyCredential> = existing
        .iter()
        .map(|v| {
            serde_json::from_value(v.credential.clone())
                .map_err(|e| OidcError::Internal(e.to_string()))
        })
        .collect::<Result<_, _>>()?;
    let wa = webauthn(&state)?;
    let (challenge, registration_state) = wa.start_registration(
        user.id.as_bytes(),
        &user.email,
        user.username.as_deref().unwrap_or(&user.email),
        &credentials.iter().map(|v| v.id.clone()).collect::<Vec<_>>(),
    );
    let token = generate_opaque_token()?;
    let now = Utc::now();
    let c = MfaCeremony {
        id: generate_uuid_v7(),
        token_hash: sha2_256_hex(&token),
        user_id: user.id,
        realm_id: user.realm_id,
        client_id: None,
        purpose: "webauthn_enrollment".into(),
        state: serde_json::to_value(registration_state)
            .map_err(|e| OidcError::Internal(e.to_string()))?,
        attempts: 0,
        expires_at: now + Duration::minutes(CEREMONY_MINUTES),
        used_at: None,
        created_at: now,
    };
    MfaRepo.create_ceremony(&mut conn, &c).await?;
    Ok(Json(
        json!({"ceremony_token":token,"public_key":challenge,"expires_in":CEREMONY_MINUTES*60}),
    ))
}

pub async fn webauthn_finish_handler(
    state: OidcState,
    headers: HeaderMap,
    req: WebauthnFinishRequest,
) -> Result<Json<Value>, OidcError> {
    let user = enrollment_user(&state, &headers).await?;
    let mut conn = state.connect().await?;
    let c = MfaRepo
        .find_ceremony_for_update(&mut conn, &sha2_256_hex(&req.ceremony_token))
        .await?
        .ok_or_else(|| {
            OidcError::AuthenticationFailed("MFA challenge is invalid or expired".into())
        })?;
    valid_ceremony(&c, user.id, "webauthn_enrollment")?;
    let registration_state: RegistrationState =
        serde_json::from_value(c.state.clone()).map_err(|e| OidcError::Internal(e.to_string()))?;
    let credential = webauthn(&state)?
        .finish_registration(&registration_state, &req.response)
        .map_err(|_| {
            OidcError::AuthenticationFailed("Passkey registration could not be verified".into())
        })?;
    let value = WebauthnCredential {
        id: generate_uuid_v7(),
        user_id: user.id,
        credential_id: credential.id.to_b64url(),
        credential: serde_json::to_value(&credential)
            .map_err(|e| OidcError::Internal(e.to_string()))?,
        label: req.label.unwrap_or_else(|| "Passkey".into()),
        created_at: Utc::now(),
        last_used_at: None,
    };
    MfaRepo.save_webauthn(&mut conn, &value).await?;
    MfaRepo.use_ceremony(&mut conn, c.id).await?;
    let recovery = if MfaRepo.recovery_code_count(&mut conn, user.id).await? == 0 {
        Some(replace_recovery(&mut conn, user.id).await?)
    } else {
        None
    };
    Ok(Json(
        json!({"credential":{"id":value.id,"label":value.label,"created_at":value.created_at},"recovery_codes":recovery}),
    ))
}

pub async fn recovery_regenerate_handler(
    state: OidcState,
    headers: HeaderMap,
) -> Result<Json<Value>, OidcError> {
    let user = current_mfa_user(&state, &headers).await?;
    let mut conn = state.connect().await?;
    if MfaRepo.find_totp(&mut conn, user.id).await?.is_none()
        && MfaRepo.list_webauthn(&mut conn, user.id).await?.is_empty()
    {
        return Err(OidcError::InvalidInput(
            "Enroll an authenticator before generating recovery codes".into(),
        ));
    }
    let codes = replace_recovery(&mut conn, user.id).await?;
    Ok(Json(json!({"recovery_codes":codes})))
}
pub async fn delete_totp_handler(
    state: OidcState,
    headers: HeaderMap,
) -> Result<Json<Value>, OidcError> {
    let user = current_mfa_user(&state, &headers).await?;
    let mut conn = state.connect().await?;
    MfaRepo.delete_totp(&mut conn, user.id).await?;
    Ok(Json(json!({"deleted":true})))
}
pub async fn delete_webauthn_handler(
    state: OidcState,
    headers: HeaderMap,
    req: DeleteCredentialRequest,
) -> Result<Json<Value>, OidcError> {
    let user = current_mfa_user(&state, &headers).await?;
    let id = req
        .credential_id
        .ok_or_else(|| OidcError::InvalidInput("credential_id is required".into()))?;
    let mut conn = state.connect().await?;
    MfaRepo.delete_webauthn(&mut conn, user.id, id).await?;
    Ok(Json(json!({"deleted":true})))
}

pub async fn begin_login(
    conn: &mut Connection,
    state: &OidcState,
    user_id: Uuid,
    realm_id: Uuid,
    client_id: Uuid,
) -> Result<LoginMfaChallenge, OidcError> {
    let totp = MfaRepo.find_totp(conn, user_id).await?.is_some();
    let rows = MfaRepo.list_webauthn(conn, user_id).await?;
    let passkeys: Vec<PasskeyCredential> = rows
        .iter()
        .map(|v| {
            serde_json::from_value(v.credential.clone())
                .map_err(|e| OidcError::Internal(e.to_string()))
        })
        .collect::<Result<_, _>>()?;
    let mut methods = Vec::new();
    if totp {
        methods.push("totp".into());
    }
    if !passkeys.is_empty() {
        methods.push("webauthn".into());
    }
    if MfaRepo.recovery_code_count(conn, user_id).await? > 0 {
        methods.push("recovery_code".into());
    }
    let wa = webauthn(state)?;
    let (web_challenge, web_state) = if passkeys.is_empty() {
        (None, None)
    } else {
        let (a, b) = wa.start_authentication_with_creds_for_user(user_id.as_bytes(), &passkeys);
        (
            Some(serde_json::to_value(a).map_err(|e| OidcError::Internal(e.to_string()))?),
            Some(serde_json::to_value(b).map_err(|e| OidcError::Internal(e.to_string()))?),
        )
    };
    let token = generate_opaque_token()?;
    let now = Utc::now();
    let c = MfaCeremony {
        id: generate_uuid_v7(),
        token_hash: sha2_256_hex(&token),
        user_id,
        realm_id,
        client_id: Some(client_id),
        purpose: "login".into(),
        state: json!({"webauthn":web_state}),
        attempts: 0,
        expires_at: now + Duration::minutes(CEREMONY_MINUTES),
        used_at: None,
        created_at: now,
    };
    MfaRepo.create_ceremony(conn, &c).await?;
    Ok(LoginMfaChallenge {
        ceremony_token: token,
        methods,
        webauthn: web_challenge,
        expires_in: CEREMONY_MINUTES * 60,
    })
}

pub async fn verify_login(
    conn: &mut Connection,
    state: &OidcState,
    user_id: Uuid,
    realm_id: Uuid,
    client_id: Uuid,
    proof: &LoginMfaProof,
) -> Result<Option<VerifiedMfa>, OidcError> {
    let c = MfaRepo
        .find_ceremony_for_update(conn, &sha2_256_hex(&proof.ceremony_token))
        .await?
        .ok_or_else(|| {
            OidcError::AuthenticationFailed("MFA challenge is invalid or expired".into())
        })?;
    valid_ceremony(&c, user_id, "login")?;
    if c.realm_id != realm_id || c.client_id != Some(client_id) {
        return Err(OidcError::AuthenticationFailed(
            "MFA challenge does not match this login".into(),
        ));
    }
    let verified = if let Some(code) = proof.totp_code.as_deref() {
        if let Some(totp) = MfaRepo.find_totp(conn, user_id).await? {
            let secret = state.decrypt_sensitive_value(&totp.secret_encrypted)?;
            let matched = matching_totp_step(&secret, code.trim(), Utc::now().timestamp());
            let replayed = matched
                .zip(totp.last_used_at.map(|v| v.timestamp() / 30))
                .is_some_and(|(candidate, last)| candidate <= last);
            if matched.is_some() && !replayed {
                MfaRepo.touch_totp(conn, totp.id).await?;
                Some(vec!["pwd".into(), "otp".into(), "mfa".into()])
            } else {
                None
            }
        } else {
            None
        }
    } else if let Some(code) = proof.recovery_code.as_deref() {
        let hasher = Argon2idHasher::new();
        let mut found = None;
        for stored in MfaRepo.available_recovery_codes(conn, user_id).await? {
            if hasher
                .verify(&code.trim().to_uppercase(), &stored.code_hash)
                .unwrap_or(false)
            {
                found = Some(stored.id);
                break;
            }
        }
        if let Some(id) = found {
            MfaRepo.use_recovery_code(conn, id).await?;
            Some(vec!["pwd".into(), "recovery".into(), "mfa".into()])
        } else {
            None
        }
    } else if let Some(response) = proof.webauthn_response.as_ref() {
        let state_value = c.state.get("webauthn").cloned().flatten();
        if let Some(v) = state_value {
            let auth_state: AuthenticationState =
                serde_json::from_value(v).map_err(|e| OidcError::Internal(e.to_string()))?;
            let rows = MfaRepo.list_webauthn(conn, user_id).await?;
            let mut result = None;
            for row in rows {
                if row.credential_id == response.id {
                    let mut credential: PasskeyCredential =
                        serde_json::from_value(row.credential.clone())
                            .map_err(|e| OidcError::Internal(e.to_string()))?;
                    if let Ok(success) =
                        webauthn(state)?.finish_authentication(&auth_state, response, &credential)
                    {
                        credential.counter = success.new_counter;
                        let value = serde_json::to_value(credential)
                            .map_err(|e| OidcError::Internal(e.to_string()))?;
                        MfaRepo
                            .update_webauthn_counter(conn, row.id, &value)
                            .await?;
                        result = Some(vec![
                            "pwd".into(),
                            "hwk".into(),
                            "user".into(),
                            "mfa".into(),
                        ]);
                    }
                    break;
                }
            }
            result
        } else {
            None
        }
    } else {
        None
    };
    match verified {
        Some(amr) => {
            MfaRepo.use_ceremony(conn, c.id).await?;
            Ok(Some(VerifiedMfa { amr }))
        }
        None => {
            MfaRepo.fail_ceremony(conn, c.id).await?;
            Ok(None)
        }
    }
}

trait FlattenValue {
    fn flatten(self) -> Option<Value>;
}
impl FlattenValue for Option<Value> {
    fn flatten(self) -> Option<Value> {
        self.and_then(|v| if v.is_null() { None } else { Some(v) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rfc6238_sha1_vector() {
        let secret = b"12345678901234567890";
        assert_eq!(totp_at(secret, 59 / 30), "287082");
    }
    #[test]
    fn totp_window_and_format() {
        let secret = b"12345678901234567890";
        assert!(verify_totp(secret, "287082", 59));
        assert!(!verify_totp(secret, "287083", 59));
        assert!(!verify_totp(secret, "12x456", 59));
    }
    #[test]
    fn base32_known_value() {
        assert_eq!(base32(b"foobar"), "MZXW6YTBOI");
    }
}
