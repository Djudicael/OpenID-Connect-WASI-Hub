//! In-memory mock implementations of repository traits and token service.
//!
//! These mocks are intended for unit testing domain logic without a database.
//! All repos use `std::sync::RwLock` for WASM compatibility.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::RwLock;

use async_trait::async_trait;
use uuid::Uuid;

use crate::errors::OidcError;
use crate::models::ApiKey;
use crate::models::ResponseType;
use crate::models::audit_event::{ActorType, AuditEvent};
use crate::models::auth_code::AuthCode;
use crate::models::client::{Client, ClientType};
use crate::models::realm::Realm;
use crate::models::session::Session;
use crate::models::signing_key::{Algorithm, SigningKey};
use crate::models::user::User;
use crate::traits::token_service::{IdTokenExtraClaims, TokenService, VerifiedAccessToken};

// ---------------------------------------------------------------------------
// InMemoryUserRepo
// ---------------------------------------------------------------------------

/// In-memory mock of a User repository.
pub struct InMemoryUserRepo {
    users: RwLock<HashMap<Uuid, User>>,
}

impl InMemoryUserRepo {
    /// Create an empty repo.
    pub fn new() -> Self {
        Self {
            users: RwLock::new(HashMap::new()),
        }
    }

    /// Find a user by primary key (excludes soft-deleted).
    pub async fn find_by_id(&self, id: Uuid) -> Result<Option<User>, OidcError> {
        let users = self
            .users
            .read()
            .map_err(|e| OidcError::Internal(e.to_string()))?;
        match users.get(&id) {
            Some(u) if u.deleted_at.is_none() => Ok(Some(u.clone())),
            _ => Ok(None),
        }
    }

    /// Find a user by email within a realm (excludes soft-deleted).
    pub async fn find_by_email(
        &self,
        realm_id: Uuid,
        email: &str,
    ) -> Result<Option<User>, OidcError> {
        let users = self
            .users
            .read()
            .map_err(|e| OidcError::Internal(e.to_string()))?;
        for u in users.values() {
            if u.realm_id == realm_id && u.email == email && u.deleted_at.is_none() {
                return Ok(Some(u.clone()));
            }
        }
        Ok(None)
    }

    /// Insert a new user.
    pub async fn create(&self, entity: &User) -> Result<(), OidcError> {
        let mut users = self
            .users
            .write()
            .map_err(|e| OidcError::Internal(e.to_string()))?;
        users.insert(entity.id, entity.clone());
        Ok(())
    }

    /// Update an existing user.
    pub async fn update(&self, entity: &User) -> Result<(), OidcError> {
        let mut users = self
            .users
            .write()
            .map_err(|e| OidcError::Internal(e.to_string()))?;
        users.insert(entity.id, entity.clone());
        Ok(())
    }

    /// Soft-delete a user by ID.
    pub async fn soft_delete(&self, id: Uuid) -> Result<(), OidcError> {
        let mut users = self
            .users
            .write()
            .map_err(|e| OidcError::Internal(e.to_string()))?;
        if let Some(u) = users.get_mut(&id) {
            u.deleted_at = Some(chrono::Utc::now());
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// InMemoryRealmRepo
// ---------------------------------------------------------------------------

/// In-memory mock of a Realm repository.
pub struct InMemoryRealmRepo {
    realms: RwLock<HashMap<Uuid, Realm>>,
}

impl InMemoryRealmRepo {
    /// Create an empty repo.
    pub fn new() -> Self {
        Self {
            realms: RwLock::new(HashMap::new()),
        }
    }

    /// Find a realm by primary key (excludes soft-deleted).
    pub async fn find_by_id(&self, id: Uuid) -> Result<Option<Realm>, OidcError> {
        let realms = self
            .realms
            .read()
            .map_err(|e| OidcError::Internal(e.to_string()))?;
        match realms.get(&id) {
            Some(r) if r.deleted_at.is_none() => Ok(Some(r.clone())),
            _ => Ok(None),
        }
    }

    /// Find a realm by name (excludes soft-deleted).
    pub async fn find_by_name(&self, name: &str) -> Result<Option<Realm>, OidcError> {
        let realms = self
            .realms
            .read()
            .map_err(|e| OidcError::Internal(e.to_string()))?;
        for r in realms.values() {
            if r.name == name && r.deleted_at.is_none() {
                return Ok(Some(r.clone()));
            }
        }
        Ok(None)
    }

    /// Insert a new realm.
    pub async fn create(&self, entity: &Realm) -> Result<(), OidcError> {
        let mut realms = self
            .realms
            .write()
            .map_err(|e| OidcError::Internal(e.to_string()))?;
        realms.insert(entity.id, entity.clone());
        Ok(())
    }

    /// Update an existing realm.
    pub async fn update(&self, entity: &Realm) -> Result<(), OidcError> {
        let mut realms = self
            .realms
            .write()
            .map_err(|e| OidcError::Internal(e.to_string()))?;
        realms.insert(entity.id, entity.clone());
        Ok(())
    }

    /// Soft-delete a realm by ID.
    pub async fn soft_delete(&self, id: Uuid) -> Result<(), OidcError> {
        let mut realms = self
            .realms
            .write()
            .map_err(|e| OidcError::Internal(e.to_string()))?;
        if let Some(r) = realms.get_mut(&id) {
            r.deleted_at = Some(chrono::Utc::now());
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// InMemoryClientRepo
// ---------------------------------------------------------------------------

/// In-memory mock of a Client repository.
pub struct InMemoryClientRepo {
    clients: RwLock<HashMap<Uuid, Client>>,
}

impl InMemoryClientRepo {
    /// Create an empty repo.
    pub fn new() -> Self {
        Self {
            clients: RwLock::new(HashMap::new()),
        }
    }

    /// Find a client by primary key (excludes soft-deleted).
    pub async fn find_by_id(&self, id: Uuid) -> Result<Option<Client>, OidcError> {
        let clients = self
            .clients
            .read()
            .map_err(|e| OidcError::Internal(e.to_string()))?;
        match clients.get(&id) {
            Some(c) if c.deleted_at.is_none() => Ok(Some(c.clone())),
            _ => Ok(None),
        }
    }

    /// Find a client by its client_id string (excludes soft-deleted).
    pub async fn find_by_client_id(&self, client_id: &str) -> Result<Option<Client>, OidcError> {
        let clients = self
            .clients
            .read()
            .map_err(|e| OidcError::Internal(e.to_string()))?;
        for c in clients.values() {
            if c.client_id == client_id && c.deleted_at.is_none() {
                return Ok(Some(c.clone()));
            }
        }
        Ok(None)
    }

    /// Insert a new client.
    pub async fn create(&self, entity: &Client) -> Result<(), OidcError> {
        let mut clients = self
            .clients
            .write()
            .map_err(|e| OidcError::Internal(e.to_string()))?;
        clients.insert(entity.id, entity.clone());
        Ok(())
    }

    /// Update an existing client.
    pub async fn update(&self, entity: &Client) -> Result<(), OidcError> {
        let mut clients = self
            .clients
            .write()
            .map_err(|e| OidcError::Internal(e.to_string()))?;
        clients.insert(entity.id, entity.clone());
        Ok(())
    }

    /// Soft-delete a client by ID.
    pub async fn soft_delete(&self, id: Uuid) -> Result<(), OidcError> {
        let mut clients = self
            .clients
            .write()
            .map_err(|e| OidcError::Internal(e.to_string()))?;
        if let Some(c) = clients.get_mut(&id) {
            c.deleted_at = Some(chrono::Utc::now());
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// InMemorySessionRepo
// ---------------------------------------------------------------------------

/// In-memory mock of a Session repository.
pub struct InMemorySessionRepo {
    sessions: RwLock<HashMap<Uuid, Session>>,
}

impl InMemorySessionRepo {
    /// Create an empty repo.
    pub fn new() -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
        }
    }

    /// Find a session by primary key.
    pub async fn find_by_id(&self, id: Uuid) -> Result<Option<Session>, OidcError> {
        let sessions = self
            .sessions
            .read()
            .map_err(|e| OidcError::Internal(e.to_string()))?;
        Ok(sessions.get(&id).cloned())
    }

    /// Find a non-revoked, non-expired session by access token hash.
    pub async fn find_by_access_token_hash(
        &self,
        hash: &str,
    ) -> Result<Option<Session>, OidcError> {
        let sessions = self
            .sessions
            .read()
            .map_err(|e| OidcError::Internal(e.to_string()))?;
        for s in sessions.values() {
            if s.access_token_hash == hash && !s.revoked && s.expires_at > chrono::Utc::now() {
                return Ok(Some(s.clone()));
            }
        }
        Ok(None)
    }

    /// Find a non-revoked session by refresh token hash.
    pub async fn find_by_refresh_token_hash(
        &self,
        hash: &str,
    ) -> Result<Option<Session>, OidcError> {
        let sessions = self
            .sessions
            .read()
            .map_err(|e| OidcError::Internal(e.to_string()))?;
        for s in sessions.values() {
            if s.refresh_token_hash.as_deref() == Some(hash) && !s.revoked {
                return Ok(Some(s.clone()));
            }
        }
        Ok(None)
    }

    /// Insert a new session.
    pub async fn create(&self, entity: &Session) -> Result<(), OidcError> {
        let mut sessions = self
            .sessions
            .write()
            .map_err(|e| OidcError::Internal(e.to_string()))?;
        sessions.insert(entity.id, entity.clone());
        Ok(())
    }

    /// Revoke a session by ID.
    pub async fn revoke(&self, id: Uuid) -> Result<(), OidcError> {
        let mut sessions = self
            .sessions
            .write()
            .map_err(|e| OidcError::Internal(e.to_string()))?;
        if let Some(s) = sessions.get_mut(&id) {
            s.revoked = true;
        }
        Ok(())
    }

    /// Mark a session as rotated (sets rotated_at to now).
    pub async fn mark_rotated(&self, id: Uuid) -> Result<(), OidcError> {
        let mut sessions = self
            .sessions
            .write()
            .map_err(|e| OidcError::Internal(e.to_string()))?;
        if let Some(s) = sessions.get_mut(&id) {
            s.rotated_at = Some(chrono::Utc::now());
        }
        Ok(())
    }

    /// Mark a session as reused (token theft detection).
    pub async fn mark_reused(&self, id: Uuid) -> Result<(), OidcError> {
        let mut sessions = self
            .sessions
            .write()
            .map_err(|e| OidcError::Internal(e.to_string()))?;
        if let Some(s) = sessions.get_mut(&id) {
            s.reused_at = Some(chrono::Utc::now());
        }
        Ok(())
    }

    /// Revoke all sessions in a token family.
    pub async fn revoke_family(&self, family_id: Uuid) -> Result<(), OidcError> {
        let mut sessions = self
            .sessions
            .write()
            .map_err(|e| OidcError::Internal(e.to_string()))?;
        for s in sessions.values_mut() {
            if s.token_family_id == Some(family_id) {
                s.revoked = true;
                s.family_revoked = true;
            }
        }
        Ok(())
    }

    /// Revoke all active sessions for a user.
    pub async fn revoke_by_user_id(&self, user_id: Uuid) -> Result<(), OidcError> {
        let mut sessions = self
            .sessions
            .write()
            .map_err(|e| OidcError::Internal(e.to_string()))?;
        for s in sessions.values_mut() {
            if s.user_id == Some(user_id) && !s.revoked {
                s.revoked = true;
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// InMemoryApiKeyRepo
// ---------------------------------------------------------------------------

/// In-memory mock of an ApiKey repository.
pub struct InMemoryApiKeyRepo {
    keys: RwLock<HashMap<Uuid, ApiKey>>,
}

impl InMemoryApiKeyRepo {
    /// Create an empty repo.
    pub fn new() -> Self {
        Self {
            keys: RwLock::new(HashMap::new()),
        }
    }

    /// Find an API key by primary key.
    pub async fn find_by_id(&self, id: Uuid) -> Result<Option<ApiKey>, OidcError> {
        let keys = self
            .keys
            .read()
            .map_err(|e| OidcError::Internal(e.to_string()))?;
        Ok(keys.get(&id).cloned())
    }

    /// Find an active API key by prefix.
    pub async fn find_by_prefix(&self, prefix: &str) -> Result<Option<ApiKey>, OidcError> {
        let keys = self
            .keys
            .read()
            .map_err(|e| OidcError::Internal(e.to_string()))?;
        for k in keys.values() {
            if k.prefix == prefix && !k.revoked && k.is_active() {
                return Ok(Some(k.clone()));
            }
        }
        Ok(None)
    }

    /// Find all API keys for a realm.
    pub async fn find_by_realm(
        &self,
        realm_id: Uuid,
        include_revoked: bool,
    ) -> Result<Vec<ApiKey>, OidcError> {
        let keys = self
            .keys
            .read()
            .map_err(|e| OidcError::Internal(e.to_string()))?;
        let mut result: Vec<ApiKey> = keys
            .values()
            .filter(|k| k.realm_id == realm_id && (include_revoked || !k.revoked))
            .cloned()
            .collect();
        result.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        Ok(result)
    }

    /// Insert a new API key.
    pub async fn create(&self, entity: &ApiKey) -> Result<(), OidcError> {
        let mut keys = self
            .keys
            .write()
            .map_err(|e| OidcError::Internal(e.to_string()))?;
        keys.insert(entity.id, entity.clone());
        Ok(())
    }

    /// Revoke an API key by ID.
    pub async fn revoke(&self, id: Uuid) -> Result<(), OidcError> {
        let mut keys = self
            .keys
            .write()
            .map_err(|e| OidcError::Internal(e.to_string()))?;
        if let Some(k) = keys.get_mut(&id) {
            k.revoked = true;
        }
        Ok(())
    }

    /// Increment the request count for an API key.
    pub async fn increment_count(&self, id: Uuid) -> Result<(), OidcError> {
        let mut keys = self
            .keys
            .write()
            .map_err(|e| OidcError::Internal(e.to_string()))?;
        if let Some(k) = keys.get_mut(&id) {
            k.request_count += 1;
            k.last_used_at = Some(chrono::Utc::now());
        }
        Ok(())
    }

    /// Mark an API key as rotated.
    pub async fn mark_rotated(&self, id: Uuid) -> Result<(), OidcError> {
        let mut keys = self
            .keys
            .write()
            .map_err(|e| OidcError::Internal(e.to_string()))?;
        if let Some(k) = keys.get_mut(&id) {
            k.rotated_at = Some(chrono::Utc::now());
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// InMemoryAuthCodeRepo
// ---------------------------------------------------------------------------

/// In-memory mock of an AuthCode repository.
pub struct InMemoryAuthCodeRepo {
    codes: RwLock<HashMap<Uuid, AuthCode>>,
}

impl InMemoryAuthCodeRepo {
    /// Create an empty repo.
    pub fn new() -> Self {
        Self {
            codes: RwLock::new(HashMap::new()),
        }
    }

    /// Find an active (unused, unexpired) authorization code by its code string.
    pub async fn find_by_code(&self, code: &str) -> Result<Option<AuthCode>, OidcError> {
        let codes = self
            .codes
            .read()
            .map_err(|e| OidcError::Internal(e.to_string()))?;
        for ac in codes.values() {
            if ac.code == code && !ac.used && ac.expires_at > chrono::Utc::now() {
                return Ok(Some(ac.clone()));
            }
        }
        Ok(None)
    }

    /// Insert a new authorization code.
    pub async fn create(&self, entity: &AuthCode) -> Result<(), OidcError> {
        let mut codes = self
            .codes
            .write()
            .map_err(|e| OidcError::Internal(e.to_string()))?;
        codes.insert(entity.id, entity.clone());
        Ok(())
    }

    /// Mark an authorization code as used.
    pub async fn mark_used(&self, id: Uuid) -> Result<(), OidcError> {
        let mut codes = self
            .codes
            .write()
            .map_err(|e| OidcError::Internal(e.to_string()))?;
        if let Some(ac) = codes.get_mut(&id) {
            ac.used = true;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// InMemorySigningKeyRepo
// ---------------------------------------------------------------------------

/// In-memory mock of a SigningKey repository.
pub struct InMemorySigningKeyRepo {
    keys: RwLock<HashMap<Uuid, SigningKey>>,
}

impl InMemorySigningKeyRepo {
    /// Create an empty repo.
    pub fn new() -> Self {
        Self {
            keys: RwLock::new(HashMap::new()),
        }
    }

    /// Find a signing key by primary key.
    pub async fn find_by_id(&self, id: Uuid) -> Result<Option<SigningKey>, OidcError> {
        let keys = self
            .keys
            .read()
            .map_err(|e| OidcError::Internal(e.to_string()))?;
        Ok(keys.get(&id).cloned())
    }

    /// Find all active signing keys for a realm.
    pub async fn find_active_by_realm(&self, realm_id: Uuid) -> Result<Vec<SigningKey>, OidcError> {
        let keys = self
            .keys
            .read()
            .map_err(|e| OidcError::Internal(e.to_string()))?;
        Ok(keys
            .values()
            .filter(|k| k.realm_id == realm_id && k.active)
            .cloned()
            .collect())
    }

    /// Insert a new signing key.
    pub async fn create(&self, entity: &SigningKey) -> Result<(), OidcError> {
        let mut keys = self
            .keys
            .write()
            .map_err(|e| OidcError::Internal(e.to_string()))?;
        keys.insert(entity.id, entity.clone());
        Ok(())
    }

    /// Delete (retire) a signing key by ID.
    pub async fn delete(&self, id: Uuid) -> Result<(), OidcError> {
        let mut keys = self
            .keys
            .write()
            .map_err(|e| OidcError::Internal(e.to_string()))?;
        keys.remove(&id);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// InMemoryAuditEventRepo
// ---------------------------------------------------------------------------

/// In-memory mock of an AuditEvent repository.
pub struct InMemoryAuditEventRepo {
    events: RwLock<Vec<AuditEvent>>,
}

impl InMemoryAuditEventRepo {
    /// Create an empty repo.
    pub fn new() -> Self {
        Self {
            events: RwLock::new(Vec::new()),
        }
    }

    /// Find an audit event by primary key.
    pub async fn find_by_id(&self, id: Uuid) -> Result<Option<AuditEvent>, OidcError> {
        let events = self
            .events
            .read()
            .map_err(|e| OidcError::Internal(e.to_string()))?;
        Ok(events.iter().find(|e| e.id == id).cloned())
    }

    /// Find audit events for a realm with pagination and optional filters.
    pub async fn find_by_realm(
        &self,
        realm_id: Uuid,
        limit: i64,
        offset: i64,
        event_type: Option<&str>,
        from: Option<chrono::DateTime<chrono::Utc>>,
        to: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<Vec<AuditEvent>, OidcError> {
        let events = self
            .events
            .read()
            .map_err(|e| OidcError::Internal(e.to_string()))?;
        let mut filtered: Vec<&AuditEvent> = events
            .iter()
            .filter(|e| {
                e.realm_id == Some(realm_id)
                    && event_type.map_or(true, |et| e.event_type == et)
                    && from.map_or(true, |f| e.created_at >= f)
                    && to.map_or(true, |t| e.created_at <= t)
            })
            .collect();
        // Sort by created_at DESC
        filtered.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        let result: Vec<AuditEvent> = filtered
            .into_iter()
            .skip(offset as usize)
            .take(limit as usize)
            .cloned()
            .collect();
        Ok(result)
    }

    /// Insert a new audit event.
    pub async fn create(&self, entity: &AuditEvent) -> Result<(), OidcError> {
        let mut events = self
            .events
            .write()
            .map_err(|e| OidcError::Internal(e.to_string()))?;
        events.push(entity.clone());
        Ok(())
    }

    /// Count recent failed login attempts for a user identified by email in a realm.
    ///
    /// Looks up the user by email and counts `LOGIN_FAILURE` events within the
    /// last 5 minutes.
    pub async fn count_recent_failures(
        &self,
        email: &str,
        realm_id: Uuid,
    ) -> Result<i64, OidcError> {
        let events = self
            .events
            .read()
            .map_err(|e| OidcError::Internal(e.to_string()))?;
        let cutoff = chrono::Utc::now() - chrono::Duration::minutes(5);
        let count = events
            .iter()
            .filter(|e| {
                e.event_type == "LOGIN_FAILURE"
                    && e.realm_id == Some(realm_id)
                    && e.created_at > cutoff
                    && e.details.get("email").and_then(|v| v.as_str()) == Some(email)
            })
            .count();
        Ok(count as i64)
    }

    /// List recent audit events across all realms with optional filtering.
    pub async fn list_recent(
        &self,
        limit: i64,
        offset: i64,
        event_type: Option<&str>,
        actor_id: Option<&Uuid>,
        from: Option<chrono::DateTime<chrono::Utc>>,
        to: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<Vec<AuditEvent>, OidcError> {
        let events = self
            .events
            .read()
            .map_err(|e| OidcError::Internal(e.to_string()))?;
        let mut filtered: Vec<&AuditEvent> = events
            .iter()
            .filter(|e| {
                event_type.map_or(true, |et| e.event_type == et)
                    && actor_id.map_or(true, |aid| e.actor_id == Some(*aid))
                    && from.map_or(true, |f| e.created_at >= f)
                    && to.map_or(true, |t| e.created_at <= t)
            })
            .collect();
        filtered.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        let result: Vec<AuditEvent> = filtered
            .into_iter()
            .skip(offset as usize)
            .take(limit as usize)
            .cloned()
            .collect();
        Ok(result)
    }

    /// Count audit events with optional filtering.
    pub async fn count(
        &self,
        realm_id: Option<Uuid>,
        event_type: Option<&str>,
        actor_id: Option<&Uuid>,
        from: Option<chrono::DateTime<chrono::Utc>>,
        to: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<i64, OidcError> {
        let events = self
            .events
            .read()
            .map_err(|e| OidcError::Internal(e.to_string()))?;
        let count = events
            .iter()
            .filter(|e| {
                realm_id.map_or(true, |rid| e.realm_id == Some(rid))
                    && event_type.map_or(true, |et| e.event_type == et)
                    && actor_id.map_or(true, |aid| e.actor_id == Some(*aid))
                    && from.map_or(true, |f| e.created_at >= f)
                    && to.map_or(true, |t| e.created_at <= t)
            })
            .count();
        Ok(count as i64)
    }
}

// ---------------------------------------------------------------------------
// MockTokenService
// ---------------------------------------------------------------------------

/// A mock token service that stores issued tokens in memory and verifies by
/// lookup. No real JWT cryptography — deterministic and fast for unit tests.
pub struct MockTokenService {
    access_tokens: RwLock<HashMap<String, String>>, // token -> subject
    access_claims: RwLock<HashMap<String, VerifiedAccessToken>>, // token -> claims
    id_tokens: RwLock<HashMap<String, String>>,     // token -> subject
    issuer: String,
}

impl MockTokenService {
    /// Create a new mock token service with the given issuer.
    pub fn new(issuer: &str) -> Self {
        Self {
            access_tokens: RwLock::new(HashMap::new()),
            access_claims: RwLock::new(HashMap::new()),
            id_tokens: RwLock::new(HashMap::new()),
            issuer: issuer.to_string(),
        }
    }
}

#[async_trait]
impl TokenService for MockTokenService {
    async fn issue_access_token(
        &self,
        subject: &str,
        audience: &str,
        scopes: &[String],
        _dpop_jkt: Option<&str>,
        _authorization_details: Option<&serde_json::Value>,
    ) -> Result<String, OidcError> {
        // Generate a deterministic-ish token for testing
        let token = format!("at:{}:{}:{}", subject, audience, scopes.join(","));
        let cnf = _dpop_jkt.map(|jkt| serde_json::json!({"jkt": jkt}));
        let claims = VerifiedAccessToken {
            sub: subject.to_string(),
            aud: audience.to_string(),
            iss: self.issuer.clone(),
            exp: chrono::Utc::now().timestamp() + 3600,
            iat: chrono::Utc::now().timestamp(),
            scope: scopes.join(" "),
            cnf,
            authorization_details: _authorization_details.cloned(),
        };
        self.access_tokens
            .write()
            .map_err(|e| OidcError::Internal(e.to_string()))?
            .insert(token.clone(), subject.to_string());
        self.access_claims
            .write()
            .map_err(|e| OidcError::Internal(e.to_string()))?
            .insert(token.clone(), claims);
        Ok(token)
    }

    async fn verify_access_token(&self, token: &str) -> Result<String, OidcError> {
        let tokens = self
            .access_tokens
            .read()
            .map_err(|e| OidcError::Internal(e.to_string()))?;
        tokens
            .get(token)
            .cloned()
            .ok_or_else(|| OidcError::AuthenticationFailed("invalid access token".into()))
    }

    async fn verify_access_token_with_claims(
        &self,
        token: &str,
    ) -> Result<VerifiedAccessToken, OidcError> {
        let claims = self
            .access_claims
            .read()
            .map_err(|e| OidcError::Internal(e.to_string()))?;
        claims
            .get(token)
            .cloned()
            .ok_or_else(|| OidcError::AuthenticationFailed("invalid access token".into()))
    }

    async fn issue_id_token(
        &self,
        subject: &str,
        audience: &str,
        extra: Option<IdTokenExtraClaims>,
    ) -> Result<String, OidcError> {
        let nonce_suffix = extra
            .as_ref()
            .and_then(|e| e.nonce.as_deref())
            .unwrap_or("");
        let token = format!("id:{}:{}:{}", subject, audience, nonce_suffix);
        self.id_tokens
            .write()
            .map_err(|e| OidcError::Internal(e.to_string()))?
            .insert(token.clone(), subject.to_string());
        Ok(token)
    }

    async fn verify_id_token(&self, token: &str) -> Result<String, OidcError> {
        let tokens = self
            .id_tokens
            .read()
            .map_err(|e| OidcError::Internal(e.to_string()))?;
        tokens
            .get(token)
            .cloned()
            .ok_or_else(|| OidcError::AuthenticationFailed("invalid id token".into()))
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::auth_code::CodeChallengeMethod;

    // -- Helpers to create valid test entities --

    fn test_user() -> User {
        User {
            id: Uuid::now_v7(),
            realm_id: Uuid::now_v7(),
            email: "alice@example.com".into(),
            email_verified: true,
            username: Some("alice".into()),
            password_hash: Some("$argon2id$...".into()),
            given_name: Some("Alice".into()),
            family_name: Some("Smith".into()),
            middle_name: None,
            nickname: None,
            preferred_username: None,
            profile: None,
            picture: None,
            website: None,
            gender: None,
            birthdate: None,
            zoneinfo: None,
            phone_number: None,
            phone_number_verified: None,
            locale: "en".into(),
            attributes: serde_json::Value::Object(serde_json::Map::new()),
            enabled: true,
            deleted_at: None,
            updated_at: chrono::Utc::now(),
        }
    }

    fn test_realm() -> Realm {
        Realm {
            id: Uuid::now_v7(),
            name: "production".into(),
            display_name: "Production".into(),
            enabled: true,
            config: serde_json::Value::Object(serde_json::Map::new()),
            deleted_at: None,
        }
    }

    fn test_client(realm_id: Uuid) -> Client {
        Client {
            id: Uuid::now_v7(),
            realm_id,
            client_id: "my-app".into(),
            client_type: ClientType::Confidential,
            client_secret_hash: Some("$argon2id$...".into()),
            name: "My App".into(),
            redirect_uris: vec!["https://example.com/callback".into()],
            allowed_scopes: vec!["openid".into()],
            allowed_grant_types: vec!["authorization_code".into()],
            pkce_required: true,
            enabled: true,
            deleted_at: None,
            token_endpoint_auth_method: "client_secret_basic".into(),
            jwks_uri: None,
            jwks: None,
            request_uris: vec![],
            client_secret_encrypted: None,
            frontchannel_logout_uri: None,
            frontchannel_logout_session_required: false,
            backchannel_logout_uri: None,
            backchannel_logout_session_required: false,
            post_logout_redirect_uris: vec![],
            subject_type: "public".into(),
            sector_identifier_uri: None,
            response_modes: vec!["query".to_string(), "fragment".to_string()],
            id_token_encrypted_response_alg: None,
            id_token_encrypted_response_enc: None,
            id_token_encryption_key_encrypted: None,
            id_token_encryption_key_pem: None,
        }
    }

    fn test_session(user_id: Uuid, realm_id: Uuid, client_id: Uuid) -> Session {
        Session {
            id: Uuid::now_v7(),
            sid: "test_sid_12345678".to_string(),
            user_id: Some(user_id),
            realm_id,
            client_id,
            grant_type: "authorization_code".into(),
            access_token_hash: "hash_access_123".into(),
            refresh_token_hash: Some("hash_refresh_456".into()),
            id_token_jti: Some("jti_789".into()),
            scope: vec!["openid".into(), "profile".into()],
            revoked: false,
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
            refresh_expires_at: Some(chrono::Utc::now() + chrono::Duration::days(30)),
            created_at: chrono::Utc::now(),
            last_used_at: None,
            token_family_id: Some(Uuid::now_v7()),
            previous_session_id: None,
            rotated_at: None,
            reused_at: None,
            family_revoked: false,
            authorization_details: None,
        }
    }

    fn test_api_key(realm_id: Uuid) -> ApiKey {
        ApiKey {
            id: Uuid::now_v7(),
            realm_id,
            name: "Test Key".into(),
            prefix: "abcd1234".into(),
            hashed_secret: "$argon2id$...".into(),
            scopes: vec!["read".into()],
            revoked: false,
            request_count: 0,
            expires_at: None,
            last_used_at: None,
            created_at: chrono::Utc::now(),
            created_by: None,
            rotated_at: None,
        }
    }

    fn test_auth_code(client_id: Uuid, user_id: Uuid, realm_id: Uuid) -> AuthCode {
        AuthCode {
            id: Uuid::now_v7(),
            code: "auth_code_abc123".into(),
            client_id,
            user_id,
            realm_id,
            redirect_uri: "https://example.com/callback".into(),
            scope: vec!["openid".into()],
            code_challenge: "challenge_xyz".into(),
            code_challenge_method: CodeChallengeMethod::S256,
            nonce: Some("nonce_123".into()),
            used: false,
            claims_request: None,
            display: None,
            response_type: ResponseType::CODE,
            acr_values: vec![],
            expires_at: chrono::Utc::now() + chrono::Duration::minutes(10),
            response_mode: None,
            authorization_details: None,
        }
    }

    fn test_signing_key(realm_id: Uuid) -> SigningKey {
        SigningKey {
            id: Uuid::now_v7(),
            realm_id,
            kid: "key-2024-01".into(),
            algorithm: Algorithm::Rs256,
            public_key_pem: "-----BEGIN PUBLIC KEY-----\nMIIBIj...".into(),
            private_key_pem_encrypted: Some("ENCRYPTED...".into()),
            active: true,
            created_at: chrono::Utc::now(),
            expires_at: Some(chrono::Utc::now() + chrono::Duration::days(365)),
            retired_at: None,
        }
    }

    fn test_audit_event(realm_id: Uuid) -> AuditEvent {
        AuditEvent {
            id: Uuid::now_v7(),
            realm_id: Some(realm_id),
            event_type: "user.login".into(),
            actor_id: Some(Uuid::now_v7()),
            actor_type: ActorType::User,
            target_type: Some("user".into()),
            target_id: Some(Uuid::now_v7()),
            details: serde_json::json!({"ip": "127.0.0.1"}),
            ip_address: Some("127.0.0.1".parse::<IpAddr>().unwrap()),
            user_agent: Some("test-agent".into()),
            created_at: chrono::Utc::now(),
        }
    }

    // -- InMemoryUserRepo tests --

    #[tokio::test]
    async fn test_user_repo_crud_roundtrip() {
        let repo = InMemoryUserRepo::new();
        let user = test_user();

        // Create
        repo.create(&user).await.unwrap();

        // Find by ID
        let found = repo.find_by_id(user.id).await.unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().email, "alice@example.com");

        // Find by email
        let found = repo
            .find_by_email(user.realm_id, "alice@example.com")
            .await
            .unwrap();
        assert!(found.is_some());

        // Update
        let mut updated = user.clone();
        updated.email = "bob@example.com".into();
        repo.update(&updated).await.unwrap();
        let found = repo.find_by_id(user.id).await.unwrap().unwrap();
        assert_eq!(found.email, "bob@example.com");

        // Soft delete
        repo.soft_delete(user.id).await.unwrap();
        let found = repo.find_by_id(user.id).await.unwrap();
        assert!(found.is_none());

        // Find by email should also exclude soft-deleted
        let found = repo
            .find_by_email(user.realm_id, "bob@example.com")
            .await
            .unwrap();
        assert!(found.is_none());
    }

    // -- InMemoryRealmRepo tests --

    #[tokio::test]
    async fn test_realm_repo_crud_roundtrip() {
        let repo = InMemoryRealmRepo::new();
        let realm = test_realm();

        // Create
        repo.create(&realm).await.unwrap();

        // Find by ID
        let found = repo.find_by_id(realm.id).await.unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().name, "production");

        // Find by name
        let found = repo.find_by_name("production").await.unwrap();
        assert!(found.is_some());

        // Update
        let mut updated = realm.clone();
        updated.name = "staging".into();
        repo.update(&updated).await.unwrap();
        let found = repo.find_by_id(realm.id).await.unwrap().unwrap();
        assert_eq!(found.name, "staging");

        // Soft delete
        repo.soft_delete(realm.id).await.unwrap();
        let found = repo.find_by_id(realm.id).await.unwrap();
        assert!(found.is_none());

        // Find by name should also exclude soft-deleted
        let found = repo.find_by_name("staging").await.unwrap();
        assert!(found.is_none());
    }

    // -- InMemoryClientRepo tests --

    #[tokio::test]
    async fn test_client_repo_crud_roundtrip() {
        let realm_id = Uuid::now_v7();
        let repo = InMemoryClientRepo::new();
        let client = test_client(realm_id);

        // Create
        repo.create(&client).await.unwrap();

        // Find by ID
        let found = repo.find_by_id(client.id).await.unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().client_id, "my-app");

        // Find by client_id
        let found = repo.find_by_client_id("my-app").await.unwrap();
        assert!(found.is_some());

        // Update
        let mut updated = client.clone();
        updated.name = "Updated App".into();
        repo.update(&updated).await.unwrap();
        let found = repo.find_by_id(client.id).await.unwrap().unwrap();
        assert_eq!(found.name, "Updated App");

        // Soft delete
        repo.soft_delete(client.id).await.unwrap();
        let found = repo.find_by_id(client.id).await.unwrap();
        assert!(found.is_none());

        // Find by client_id should also exclude soft-deleted
        let found = repo.find_by_client_id("my-app").await.unwrap();
        assert!(found.is_none());
    }

    // -- InMemorySessionRepo tests --

    #[tokio::test]
    async fn test_session_repo_crud_roundtrip() {
        let user_id = Uuid::now_v7();
        let realm_id = Uuid::now_v7();
        let client_id = Uuid::now_v7();
        let repo = InMemorySessionRepo::new();
        let session = test_session(user_id, realm_id, client_id);

        // Create
        repo.create(&session).await.unwrap();

        // Find by ID
        let found = repo.find_by_id(session.id).await.unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().access_token_hash, "hash_access_123");

        // Find by access token hash
        let found = repo
            .find_by_access_token_hash("hash_access_123")
            .await
            .unwrap();
        assert!(found.is_some());

        // Find by refresh token hash
        let found = repo
            .find_by_refresh_token_hash("hash_refresh_456")
            .await
            .unwrap();
        assert!(found.is_some());

        // Revoke
        repo.revoke(session.id).await.unwrap();
        let found = repo.find_by_id(session.id).await.unwrap().unwrap();
        assert!(found.revoked);

        // After revocation, find_by_access_token_hash should return None
        let found = repo
            .find_by_access_token_hash("hash_access_123")
            .await
            .unwrap();
        assert!(found.is_none());
    }

    #[tokio::test]
    async fn test_session_repo_mark_rotated_and_reused() {
        let user_id = Uuid::now_v7();
        let realm_id = Uuid::now_v7();
        let client_id = Uuid::now_v7();
        let repo = InMemorySessionRepo::new();
        let session = test_session(user_id, realm_id, client_id);

        repo.create(&session).await.unwrap();

        // Mark rotated
        repo.mark_rotated(session.id).await.unwrap();
        let found = repo.find_by_id(session.id).await.unwrap().unwrap();
        assert!(found.rotated_at.is_some());

        // Mark reused
        repo.mark_reused(session.id).await.unwrap();
        let found = repo.find_by_id(session.id).await.unwrap().unwrap();
        assert!(found.reused_at.is_some());
    }

    #[tokio::test]
    async fn test_session_repo_revoke_family() {
        let user_id = Uuid::now_v7();
        let realm_id = Uuid::now_v7();
        let client_id = Uuid::now_v7();
        let family_id = Uuid::now_v7();
        let repo = InMemorySessionRepo::new();

        let mut s1 = test_session(user_id, realm_id, client_id);
        s1.token_family_id = Some(family_id);
        let mut s2 = test_session(user_id, realm_id, client_id);
        s2.token_family_id = Some(family_id);
        let mut s3 = test_session(user_id, realm_id, client_id);
        s3.token_family_id = Some(Uuid::now_v7()); // different family

        repo.create(&s1).await.unwrap();
        repo.create(&s2).await.unwrap();
        repo.create(&s3).await.unwrap();

        repo.revoke_family(family_id).await.unwrap();

        let found1 = repo.find_by_id(s1.id).await.unwrap().unwrap();
        let found2 = repo.find_by_id(s2.id).await.unwrap().unwrap();
        let found3 = repo.find_by_id(s3.id).await.unwrap().unwrap();

        assert!(found1.revoked);
        assert!(found1.family_revoked);
        assert!(found2.revoked);
        assert!(found2.family_revoked);
        assert!(!found3.revoked); // different family
    }

    #[tokio::test]
    async fn test_session_repo_revoke_by_user_id() {
        let user_id = Uuid::now_v7();
        let realm_id = Uuid::now_v7();
        let client_id = Uuid::now_v7();
        let repo = InMemorySessionRepo::new();

        let s1 = test_session(user_id, realm_id, client_id);
        let s2 = test_session(user_id, realm_id, client_id);
        let s3 = test_session(Uuid::now_v7(), realm_id, client_id); // different user

        repo.create(&s1).await.unwrap();
        repo.create(&s2).await.unwrap();
        repo.create(&s3).await.unwrap();

        repo.revoke_by_user_id(user_id).await.unwrap();

        let found1 = repo.find_by_id(s1.id).await.unwrap().unwrap();
        let found2 = repo.find_by_id(s2.id).await.unwrap().unwrap();
        let found3 = repo.find_by_id(s3.id).await.unwrap().unwrap();

        assert!(found1.revoked);
        assert!(found2.revoked);
        assert!(!found3.revoked); // different user
    }

    // -- InMemoryApiKeyRepo tests --

    #[tokio::test]
    async fn test_api_key_repo_crud_roundtrip() {
        let realm_id = Uuid::now_v7();
        let repo = InMemoryApiKeyRepo::new();
        let key = test_api_key(realm_id);

        // Create
        repo.create(&key).await.unwrap();

        // Find by ID
        let found = repo.find_by_id(key.id).await.unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().prefix, "abcd1234");

        // Find by prefix
        let found = repo.find_by_prefix("abcd1234").await.unwrap();
        assert!(found.is_some());

        // Find by realm
        let found = repo.find_by_realm(realm_id, false).await.unwrap();
        assert_eq!(found.len(), 1);

        // Revoke
        repo.revoke(key.id).await.unwrap();
        let found = repo.find_by_id(key.id).await.unwrap().unwrap();
        assert!(found.revoked);

        // After revocation, find_by_prefix should return None (active only)
        let found = repo.find_by_prefix("abcd1234").await.unwrap();
        assert!(found.is_none());
    }

    #[tokio::test]
    async fn test_api_key_repo_increment_count() {
        let realm_id = Uuid::now_v7();
        let repo = InMemoryApiKeyRepo::new();
        let key = test_api_key(realm_id);

        repo.create(&key).await.unwrap();

        repo.increment_count(key.id).await.unwrap();
        repo.increment_count(key.id).await.unwrap();

        let found = repo.find_by_id(key.id).await.unwrap().unwrap();
        assert_eq!(found.request_count, 2);
        assert!(found.last_used_at.is_some());
    }

    #[tokio::test]
    async fn test_api_key_repo_mark_rotated() {
        let realm_id = Uuid::now_v7();
        let repo = InMemoryApiKeyRepo::new();
        let key = test_api_key(realm_id);

        repo.create(&key).await.unwrap();
        repo.mark_rotated(key.id).await.unwrap();

        let found = repo.find_by_id(key.id).await.unwrap().unwrap();
        assert!(found.rotated_at.is_some());
    }

    // -- InMemoryAuthCodeRepo tests --

    #[tokio::test]
    async fn test_auth_code_repo_crud_roundtrip() {
        let client_id = Uuid::now_v7();
        let user_id = Uuid::now_v7();
        let realm_id = Uuid::now_v7();
        let repo = InMemoryAuthCodeRepo::new();
        let code = test_auth_code(client_id, user_id, realm_id);

        // Create
        repo.create(&code).await.unwrap();

        // Find by code
        let found = repo.find_by_code("auth_code_abc123").await.unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().client_id, client_id);

        // Mark used
        repo.mark_used(code.id).await.unwrap();
        let found = repo.find_by_code("auth_code_abc123").await.unwrap();
        assert!(found.is_none()); // used codes should not be found
    }

    // -- InMemorySigningKeyRepo tests --

    #[tokio::test]
    async fn test_signing_key_repo_crud_roundtrip() {
        let realm_id = Uuid::now_v7();
        let repo = InMemorySigningKeyRepo::new();
        let key = test_signing_key(realm_id);

        // Create
        repo.create(&key).await.unwrap();

        // Find by ID
        let found = repo.find_by_id(key.id).await.unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().kid, "key-2024-01");

        // Find active by realm
        let found = repo.find_active_by_realm(realm_id).await.unwrap();
        assert_eq!(found.len(), 1);

        // Delete
        repo.delete(key.id).await.unwrap();
        let found = repo.find_by_id(key.id).await.unwrap();
        assert!(found.is_none());
    }

    // -- InMemoryAuditEventRepo tests --

    #[tokio::test]
    async fn test_audit_event_repo_crud_roundtrip() {
        let realm_id = Uuid::now_v7();
        let repo = InMemoryAuditEventRepo::new();
        let event = test_audit_event(realm_id);

        // Create
        repo.create(&event).await.unwrap();

        // Find by ID
        let found = repo.find_by_id(event.id).await.unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().event_type, "user.login");

        // Find by realm
        let found = repo
            .find_by_realm(realm_id, 10, 0, None, None, None)
            .await
            .unwrap();
        assert_eq!(found.len(), 1);
    }

    #[tokio::test]
    async fn test_audit_event_repo_count_recent_failures() {
        let realm_id = Uuid::now_v7();
        let repo = InMemoryAuditEventRepo::new();
        let email = "alice@example.com";

        // Create a LOGIN_FAILURE event with the email in details
        let failure_event = AuditEvent {
            id: Uuid::now_v7(),
            realm_id: Some(realm_id),
            event_type: "LOGIN_FAILURE".into(),
            actor_id: Some(Uuid::now_v7()),
            actor_type: ActorType::User,
            target_type: None,
            target_id: None,
            details: serde_json::json!({"email": email}),
            ip_address: None,
            user_agent: None,
            created_at: chrono::Utc::now(),
        };
        repo.create(&failure_event).await.unwrap();

        // Count recent failures
        let count = repo.count_recent_failures(email, realm_id).await.unwrap();
        assert_eq!(count, 1);

        // A different email should have 0 failures
        let count = repo
            .count_recent_failures("other@example.com", realm_id)
            .await
            .unwrap();
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn test_audit_event_repo_list_recent() {
        let realm_id = Uuid::now_v7();
        let repo = InMemoryAuditEventRepo::new();

        let e1 = test_audit_event(realm_id);
        let e2 = test_audit_event(realm_id);
        repo.create(&e1).await.unwrap();
        repo.create(&e2).await.unwrap();

        let list = repo
            .list_recent(10, 0, None, None, None, None)
            .await
            .unwrap();
        assert_eq!(list.len(), 2);
    }

    #[tokio::test]
    async fn test_audit_event_repo_count() {
        let realm_id = Uuid::now_v7();
        let repo = InMemoryAuditEventRepo::new();

        let e1 = test_audit_event(realm_id);
        let e2 = test_audit_event(realm_id);
        repo.create(&e1).await.unwrap();
        repo.create(&e2).await.unwrap();

        let count = repo.count(None, None, None, None, None).await.unwrap();
        assert_eq!(count, 2);

        let count = repo
            .count(Some(realm_id), None, None, None, None)
            .await
            .unwrap();
        assert_eq!(count, 2);

        let count = repo
            .count(Some(Uuid::now_v7()), None, None, None, None)
            .await
            .unwrap();
        assert_eq!(count, 0);
    }

    // -- MockTokenService tests --

    #[tokio::test]
    async fn test_mock_token_service_access_token_roundtrip() {
        let svc = MockTokenService::new("https://test.example.com");

        let token = svc
            .issue_access_token(
                "user-1",
                "client-1",
                &["openid".into(), "profile".into()],
                None,
                None,
            )
            .await
            .unwrap();

        // Verify returns the subject
        let sub = svc.verify_access_token(&token).await.unwrap();
        assert_eq!(sub, "user-1");

        // Verify with claims
        let claims = svc.verify_access_token_with_claims(&token).await.unwrap();
        assert_eq!(claims.sub, "user-1");
        assert_eq!(claims.aud, "client-1");
        assert_eq!(claims.iss, "https://test.example.com");
        assert_eq!(claims.scope, "openid profile");
    }

    #[tokio::test]
    async fn test_mock_token_service_invalid_access_token() {
        let svc = MockTokenService::new("https://test.example.com");

        let result = svc.verify_access_token("nonexistent").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_mock_token_service_id_token_roundtrip() {
        let svc = MockTokenService::new("https://test.example.com");

        let extra = Some(IdTokenExtraClaims {
            nonce: Some("nonce_abc".into()),
            ..Default::default()
        });
        let token = svc
            .issue_id_token("user-1", "client-1", extra)
            .await
            .unwrap();

        let sub = svc.verify_id_token(&token).await.unwrap();
        assert_eq!(sub, "user-1");
    }

    #[tokio::test]
    async fn test_mock_token_service_invalid_id_token() {
        let svc = MockTokenService::new("https://test.example.com");

        let result = svc.verify_id_token("nonexistent").await;
        assert!(result.is_err());
    }
}
