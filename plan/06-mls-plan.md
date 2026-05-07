# Messaging Layer Security (MLS) Plan

Implements **RFC 9420** (The Messaging Layer Security Protocol) for end-to-end encrypted group messaging, managed within the identity provider.

---

## 1. Goals

- **Group Management**: Create, join, leave, and remove members from MLS groups.
- **KeyPackage Handling**: Store and distribute encrypted KeyPackages.
- **Commit Processing**: Validate and apply MLS commits to update group state.
- **Epoch Safety**: Prevent replay attacks via strict epoch tracking.
- **WASI Compatibility**: All MLS operations compile to `wasm32-wasip2`.

---

## 2. Library Selection

| Library | Pure Rust | WASM Verified | Notes |
|---------|-----------|---------------|-------|
| `openmls` | Yes | To verify | Most complete, RFC 9420 compliant |
| `mls-rs` | Yes | To verify | AWS implementation, simpler API |

**Decision**: Start with `openmls`. If WASM build fails, evaluate `mls-rs` as fallback.

**Validation Criteria**:
- [ ] `cargo build --target wasm32-wasip2 -p oidc-mls` succeeds with chosen library
- [ ] MLS basic group operations pass unit tests in WASM runtime

---

## 3. Architecture

```
┌─────────────────────────────────────────────┐
│            oidc-mls Crate                    │
│  ┌─────────────┐    ┌─────────────────────┐ │
│  │ openmls Core│    │  OIDC Integration   │ │
│  │ (crypto,    │◄──►│  (users, realms,   │ │
│  │  group state│    │   KeyPackages)      │ │
│  └─────────────┘    └─────────────────────┘ │
│         │                                     │
│  ┌──────┴──────┐    ┌─────────────────────┐ │
│  │ Epoch Manager│   │  KeyPackage Store   │ │
│  │ (anti-replay)│   │  (encrypted at rest)│ │
│  └─────────────┘    └─────────────────────┘ │
└─────────────────────────────────────────────┘
```

---

## 4. Data Model

### `MlsGroup` (Domain)
```rust
pub struct MlsGroup {
    pub id: Uuid,                    // Internal DB ID
    pub group_id: GroupId,           // MLS group ID (opaque bytes)
    pub realm_id: Uuid,
    pub epoch: u64,
    pub roster_hash: [u8; 32],       // SHA-256 of member list
    pub group_state_encrypted: Vec<u8>, // AES-256-GCM encrypted MLSGroupState
    pub welcome_message: Option<Vec<u8>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
```

### `MlsMember`
```rust
pub struct MlsMember {
    pub id: Uuid,
    pub group_internal_id: Uuid,     // FK to MlsGroup.id
    pub user_id: Uuid,
    pub credential: Vec<u8>,         // MLS Credential (Basic or X.509)
    pub leaf_index: u32,
    pub added_at: DateTime<Utc>,
    pub removed_at: Option<DateTime<Utc>>,
}
```

### `KeyPackageEntry`
```rust
pub struct KeyPackageEntry {
    pub id: Uuid,
    pub user_id: Uuid,
    pub key_package_ref: Vec<u8>,    // MLS KeyPackageRef (hash)
    pub key_package_encrypted: Vec<u8>, // AES-256-GCM encrypted KeyPackage
    pub used: bool,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}
```

---

## 5. Key Management

### Application-Level Encryption Key
- AES-256-GCM key for encrypting `group_state_encrypted` and `key_package_encrypted`.
- Derived from `OIDC_MLS_MASTER_KEY` environment variable via HKDF-SHA256.
- Unique nonce per encryption: `HKDF-SHA256(key, "nonce", entry_id)`.

### MLS Credential
- Type: `BasicCredential` with Ed25519 signature keypair.
- Keypair generated per user per realm.
- Private key encrypted at rest (same AES-256-GCM key as above).

**Validation Criteria**:
- [ ] Master key never logged or exposed in error messages
- [ ] Unique nonce for every encryption operation
- [ ] Key rotation possible without re-creating groups

---

## 6. Endpoints

### Upload KeyPackage
```
POST /api/mls/key-packages
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "key_package": "base64(...)",
  "expires_in_days": 30
}
```

Response (201):
```json
{
  "id": "uuid",
  "key_package_ref": "base64(...)",
  "expires_at": "2025-06-06T00:00:00Z"
}
```

### Create Group
```
POST /api/mls/groups
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "name": "Engineering Team",
  "member_user_ids": ["uuid1", "uuid2"]
}
```

Response (201):
```json
{
  "id": "uuid",
  "group_id": "base64(...)",
  "epoch": 0,
  "welcome_message": "base64(...)",
  "members": [
    {"user_id": "uuid1", "leaf_index": 0},
    {"user_id": "uuid2", "leaf_index": 1}
  ]
}
```

### Join Group (via Welcome)
```
POST /api/mls/groups/{id}/join
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "welcome_message": "base64(...)",
  "ratchet_tree": "base64(...)"  // optional, if not in Welcome
}
```

Response (200):
```json
{
  "group_id": "base64(...)",
  "epoch": 0,
  "leaf_index": 2
}
```

### Send Commit
```
POST /api/mls/groups/{id}/commits
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "commit": "base64(...)",
  "group_info": "base64(...)"
}
```

Response (200):
```json
{
  "epoch": 5,
  "accepted": true,
  "welcome_for_new_members": "base64(...)"  // if add proposal
}
```

### Remove Member
```
POST /api/mls/groups/{id}/remove
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "user_id": "uuid"
}
```

- Server generates the remove proposal + commit on behalf of the admin.
- Returns the commit for the admin to distribute.

**Validation Criteria**:
- [ ] Only group members can send commits
- [ ] Only group creator (or designated admin) can remove members
- [ ] Commit rejected if epoch does not match current group epoch
- [ ] Welcome message valid and decryptable by invited member

---

## 7. Epoch Management & Anti-Replay

```rust
pub struct EpochManager {
    // In-memory cache (per-instance; acceptable for single-tenant WASM)
    latest_epochs: DashMap<GroupId, u64>,
}

impl EpochManager {
    pub fn validate_commit(&self, group_id: &GroupId, epoch: u64) -> Result<(), MlsError> {
        let current = self.latest_epochs.get(group_id)
            .map(|e| *e)
            .unwrap_or(0);
        
        if epoch <= current {
            return Err(MlsError::StaleEpoch { current, received: epoch });
        }
        Ok(())
    }
    
    pub fn advance(&self, group_id: &GroupId, new_epoch: u64) {
        self.latest_epochs.insert(group_id.clone(), new_epoch);
    }
}
```

**Persistence**: On every accepted commit, update `mls_groups.epoch` in PostgreSQL.

**Validation Criteria**:
- [ ] Commit with `epoch <= current` rejected with 409 Conflict
- [ ] Commit with `epoch == current + 1` accepted
- [ ] Gap in epoch sequence triggers group state re-sync
- [ ] DB epoch updated in same transaction as group state

---

## 8. Group State Persistence

### Encryption at Rest
```rust
fn encrypt_group_state(state: &[u8], key: &Aes256GcmKey, group_id: &Uuid) -> Vec<u8> {
    let nonce = derive_nonce(key, b"group_state", group_id);
    let cipher = Aes256Gcm::new(key);
    cipher.encrypt(&nonce, state).expect("encryption failure")
}
```

### Storage Flow
1. openmls produces serialized `MlsGroupState` bytes.
2. Bytes encrypted with AES-256-GCM.
3. Stored in `mls_groups.group_state_encrypted`.
4. On load: decrypt → deserialize → reconstruct `MlsGroup` object.

**Validation Criteria**:
- [ ] Group state roundtrip: save → load → identical MLS operations
- [ ] Tampered ciphertext detected (AES-GCM auth tag failure)
- [ ] Concurrent commits handled via DB row-level locking (`SELECT FOR UPDATE`)

---

## 9. WASM Considerations

| Concern | Mitigation |
|---------|------------|
| `openmls` crypto backends | Use `RustCrypto` provider (pure Rust, no ring) |
| Heap size | Limit group size to 1000 members; state streaming if needed |
| No filesystem | All keys derived from env var; no key files |
| Single-threaded | Sequential commit processing; no parallel crypto |

**Validation Criteria**:
- [ ] `wasmtime` run with `--wasi inherit-network` executes MLS endpoints
- [ ] Memory usage < 128MB for 100-member group
- [ ] KeyPackage operations complete in < 100ms

---

## 10. Checklist

- [ ] MLS library selected and WASM build verified
- [ ] `oidc-mls` crate created with domain models
- [ ] Master encryption key derivation implemented (HKDF-SHA256)
- [ ] KeyPackage upload endpoint works
- [ ] Group creation produces valid Welcome message
- [ ] Member join via Welcome succeeds
- [ ] Commit validation checks epoch
- [ ] Commit application updates group state and DB epoch atomically
- [ ] Remove member generates valid commit
- [ ] Group state encrypted at rest (AES-256-GCM)
- [ ] KeyPackages encrypted at rest
- [ ] Replay attack prevention (epoch check)
- [ ] Concurrent commit handling via DB locking
- [ ] WASM runtime integration test passes
- [ ] Memory benchmark < 128MB for 100-member group
- [ ] Performance benchmark: create group < 500ms, add member < 200ms
