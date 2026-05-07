# Master Implementation Checklist

Complete checklist for building the production-grade OpenID Connect WASI Hub. Each item includes the validation test that proves it is done.

---

## Phase 0: Project Bootstrap

| # | Task | Validation Test |
|---|------|-----------------|
| 0.1 | Create Rust workspace with 6 crates | `cargo check --workspace` passes |
| 0.2 | Add `.cargo/config.toml` with `wasm32-wasip2` target | `rustup target add wasm32-wasip2` succeeds |
| 0.3 | Configure workspace `Cargo.toml` with shared deps | `cargo tree --workspace` shows no version conflicts |
| 0.4 | Set up `rust-toolchain.toml` (stable, wasm target) | `cargo --version` matches specified toolchain |
| 0.5 | Create `plan/` directory with all 10 documents | All `.md` files present and non-empty |
| 0.6 | Initialize git repository with `.gitignore` | `git status` shows only tracked files |

---

## Phase 1: Core Domain (`oidc-core`)

| # | Task | Validation Test |
|---|------|-----------------|
| 1.1 | Define `User`, `Realm`, `Client`, `Session` models | `cargo test -p oidc-core` passes; models serialize roundtrip |
| 1.2 | Define `ApiKey`, `MlsGroup`, `MlsMember`, `KeyPackageEntry` models | Same as 1.1 |
| 1.3 | Implement `Clock` trait + `MockClock` | Deterministic: `MockClock::at(0).now()` returns fixed instant |
| 1.4 | Implement `Hasher` trait + `Argon2idHasher` | Hash verifies in < 20ms; wrong password rejected |
| 1.5 | Implement `Repository<T>` trait | `InMemoryRepository` passes all CRUD tests |
| 1.6 | Implement `TokenService` trait + `MockTokenService` | JWT issue/verify roundtrip with test keys |
| 1.7 | Add domain errors (`OidcError` enum) | All error variants convert to correct HTTP status codes |
| 1.8 | UUID v7 generation utility | Generated UUIDs are time-sortable |
| 1.9 | **Gate**: Unit tests >= 90% coverage | `cargo llvm-cov -p oidc-core --branch` >= 90% |

---

## Phase 2: Database Layer (`oidc-repository`)

| # | Task | Validation Test |
|---|------|-----------------|
| 2.1 | Create PostgreSQL schema (`V1__init.sql`) | `psql -f V1__init.sql` creates all tables without errors |
| 2.2 | Implement `Connection` wrapper (WASM + native) | `cargo build --target wasm32-wasip2 -p oidc-repository` succeeds |
| 2.3 | Implement connection pool (`wasi_pg_pool` / `deadpool`) | Pool acquire returns connection in < 100ms |
| 2.4 | Implement `UserRepository` | `find_by_id`, `find_by_email`, `create`, `update`, `soft_delete` pass |
| 2.5 | Implement `RealmRepository` | Same pattern as UserRepository |
| 2.6 | Implement `ClientRepository` | Same pattern |
| 2.7 | Implement `SessionRepository` | Token hash lookups use index; expiry cleanup query works |
| 2.8 | Implement `ApiKeyRepository` | Prefix lookup uses index; revocation updates immediately |
| 2.9 | Implement `MlsGroupRepository` | Epoch update atomic with group state |
| 2.10 | Implement `SigningKeyRepository` | JWKS query returns only active public keys |
| 2.11 | Add migration runner CLI (`oidc-migrate`) | `cargo run -p oidc-migrate -- migrate` applies all migrations |
| 2.12 | **Gate**: Native integration tests pass | `cargo test -p oidc-repository --features tokio-transport` passes |
| 2.13 | **Gate**: WASM build passes | `cargo build --target wasm32-wasip2 -p oidc-repository` succeeds |

---

## Phase 3: OIDC Protocol (`oidc-oidc`)

| # | Task | Validation Test |
|---|------|-----------------|
| 3.1 | Implement Discovery endpoint | `GET /.well-known/openid-configuration` returns valid JSON |
| 3.2 | Implement JWKS endpoint | `GET /oidc/jwks` returns RSA/EdDSA public keys with `kid` |
| 3.3 | Implement Authorization endpoint | `GET /oidc/authorize` returns 302 redirect with `code` |
| 3.4 | Implement PKCE validation | Public client without `code_challenge` rejected with 400 |
| 3.5 | Implement Token endpoint (auth code) | `POST /oidc/token` returns access_token, id_token, refresh_token |
| 3.6 | Implement Token endpoint (client credentials) | Same; no refresh_token |
| 3.7 | Implement Token endpoint (refresh token) | Old refresh token invalidated; new one issued |
| 3.8 | Implement Introspection endpoint | Active token returns claims; inactive returns `{"active":false}` |
| 3.9 | Implement Revocation endpoint | Revoked token introspects as inactive |
| 3.10 | Implement UserInfo endpoint | Returns scoped claims based on access token |
| 3.11 | Implement Logout endpoint | Session cleared; redirect to `post_logout_redirect_uri` |
| 3.12 | Implement Dynamic Client Registration | `POST /oidc/register` creates client and returns credentials |
| 3.13 | JWT signing (RS256) | JWT validates with JWKS public key |
| 3.14 | JWT signing (EdDSA) | Same |
| 3.15 | ID Token claims (`nonce`, `auth_time`, `at_hash`) | Claims present when requested |
| 3.16 | Refresh token rotation + family detection | Reused rotated token revokes entire family |
| 3.17 | **Gate**: Full OIDC flow test | Integration test: authorize -> token -> userinfo -> revoke -> introspect |
| 3.18 | **Gate**: Conformance readiness | Discovery document passes manual schema validation |

---

## Phase 4: API Key Management (`oidc-apikey`)

| # | Task | Validation Test |
|---|------|-----------------|
| 4.1 | Implement key generation (CSPRNG) | 1000 generated keys all unique; regex matches format |
| 4.2 | Implement Argon2id hashing | Hash verification < 10ms; wrong key rejected |
| 4.3 | Implement prefix extraction + lookup | Prefix search returns candidate in < 5ms |
| 4.4 | Implement constant-time verification | Timing test: verify 100 keys; stddev < 1ms |
| 4.5 | Implement scope matching (exact + wildcard) | `users:read` matches `users:read`; `*` matches all |
| 4.6 | Implement Axum extractor (`ApiKeyAuth`) | `handler(api_key: ApiKeyAuth)` compiles and runs in WASM |
| 4.7 | Implement create endpoint | `POST /api/keys` returns raw key exactly once |
| 4.8 | Implement list endpoint | `GET /api/keys` returns paginated keys without raw secrets |
| 4.9 | Implement revoke endpoint | `DELETE /api/keys/{id}` returns 204; key immediately invalid |
| 4.10 | Implement rotate endpoint | New key active; old key valid for 24h grace period |
| 4.11 | Implement usage tracking | `request_count` and `last_used_at` updated on verification |
| 4.12 | **Gate**: Lifecycle integration test | Create -> verify -> rotate -> verify old -> verify new -> revoke -> verify revoked |
| 4.13 | **Gate**: Middleware security test | Missing key 401; invalid key 401; valid key wrong scope 403 |

---

## Phase 5: MLS (`oidc-mls`)

| # | Task | Validation Test |
|---|------|-----------------|
| 5.1 | Select MLS library (`openmls` or `mls-rs`) | `cargo build --target wasm32-wasip2 -p oidc-mls` succeeds |
| 5.2 | Implement master key derivation (HKDF) | Same input always produces same key; different salts different keys |
| 5.3 | Implement AES-256-GCM encryption for group state | Roundtrip: encrypt -> decrypt -> identical bytes |
| 5.4 | Implement KeyPackage upload endpoint | `POST /api/mls/key-packages` stores encrypted KP |
| 5.5 | Implement group creation | `POST /api/mls/groups` returns valid Welcome message |
| 5.6 | Implement member join via Welcome | Client can process Welcome and join group |
| 5.7 | Implement commit sending endpoint | `POST /api/mls/groups/{id}/commits` accepts valid commit |
| 5.8 | Implement epoch validation | Commit with stale epoch rejected (409 Conflict) |
| 5.9 | Implement epoch advancement | DB epoch updated atomically with group state |
| 5.10 | Implement member removal | Admin can remove member; group state updates |
| 5.11 | Implement roster hash | Hash changes when members added/removed |
| 5.12 | **Gate**: Group lifecycle test | Create -> join 2 members -> send commit -> remove member -> group functional |
| 5.13 | **Gate**: Replay attack test | Old commit rejected after epoch advancement |
| 5.14 | **Gate**: WASM runtime test | MLS endpoints respond correctly under `wasmtime` |

---

## Phase 6: Server Assembly (`openid-connect-wasi`)

| # | Task | Validation Test |
|---|------|-----------------|
| 6.1 | Implement `AppState` | All services (DB, config, token, hasher) injectable |
| 6.2 | Implement router assembly | `app_router()` returns `Router` with all sub-routers |
| 6.3 | Implement native server starter | `cargo run` binds TCP and responds to `/health` |
| 6.4 | Implement WASI server starter | `#[wstd_axum::http_server]` main function compiles |
| 6.5 | Implement auth middleware (session + API key) | Both `Bearer` and `X-API-Key` auth work |
| 6.6 | Implement CORS layer | Preflight requests return 200 with correct headers |
| 6.7 | Implement logging middleware | Every request has `trace_id`; logs structured JSON |
| 6.8 | Implement global error handler | All errors return JSON with correct HTTP status |
| 6.9 | Implement health endpoints | `/health`, `/health/ready`, `/health/live` all respond |
| 6.10 | Serve admin static files | `/admin/` serves `front/admin/dist/` |
| 6.11 | **Gate**: Native build and test | `cargo test --workspace` passes |
| 6.12 | **Gate**: WASM build | `cargo build --target wasm32-wasip2 --release` produces `.wasm` |
| 6.13 | **Gate**: WASM runtime health | `wasmtime run` + `curl http://localhost:8080/health` returns 200 |

---

## Phase 7: Frontend (`front/admin`)

| # | Task | Validation Test |
|---|------|-----------------|
| 7.1 | Set up build system (`esbuild` + `lit-html`) | `npm run build` produces `dist/js/index.js` |
| 7.2 | Implement `BaseComponent` class | Custom element renders shadow DOM; state updates trigger re-render |
| 7.3 | Implement router (`<router-outlet>`) | Navigation to `/users` renders `users-page` component |
| 7.4 | Implement auth service (OIDC PKCE) | Login redirects to OIDC; callback exchanges code; token stored |
| 7.5 | Implement token refresh | Automatic refresh before expiry; no 401 on API calls |
| 7.6 | Implement HTTP client | All API calls include `Authorization: Bearer`; 401 redirects to login |
| 7.7 | Implement sidebar + layout | `<c-sidebar>` visible on all pages; active route highlighted |
| 7.8 | Implement dashboard page | Stats cards populated from `/api/stats` |
| 7.9 | Implement users page | Paginated table; search filters; CRUD actions |
| 7.10 | Implement clients page | Same pattern |
| 7.11 | Implement realms page | Same pattern |
| 7.12 | Implement API keys page | List with prefix; create modal shows raw key once; revoke action |
| 7.13 | Implement MLS groups page | Group list; create modal; member list; epoch display |
| 7.14 | Implement audit events page | Filterable table; pagination |
| 7.15 | Implement login page | Username/password form; error display |
| 7.16 | **Gate**: Build passes | `npm run build` exits 0 |
| 7.17 | **Gate**: E2E login flow | Playwright: login -> dashboard visible |
| 7.18 | **Gate**: E2E API key flow | Playwright: create key -> copy raw key -> revoke |

---

## Phase 8: Security Hardening

| # | Task | Validation Test |
|---|------|-----------------|
| 8.1 | All SQL queries parameterized | `grep -r "format!" crates/oidc-repository/src/` returns 0 matches in queries |
| 8.2 | Argon2id used for passwords and API keys | `cargo test` password hash tests pass |
| 8.3 | Constant-time comparison for secrets | Timing variance < 1ms across 1000 iterations |
| 8.4 | Redirect URI exact match validation | `https://a.com/callback` does NOT match `https://a.com/callback/evil` |
| 8.5 | PKCE enforced for public clients | Public client without PKCE gets `invalid_request` |
| 8.6 | Refresh token rotation + reuse detection | Reused rotated token revokes family |
| 8.7 | JWT `alg: none` rejected | Token with `alg: "none"` fails verification |
| 8.8 | Secure cookies (`HttpOnly`, `Secure`, `SameSite=Lax`) | Browser dev tools show correct flags |
| 8.9 | Security headers on all responses | `X-Frame-Options: DENY`, `HSTS` present |
| 8.10 | Rate limiting on token endpoint | 11th request from same IP in 1 min returns 429 |
| 8.11 | Secrets not logged | `grep -ri "secret\|password\|private" logs/` returns 0 matches |
| 8.12 | **Gate**: ZAP baseline scan | 0 high or critical findings |
| 8.13 | **Gate**: `cargo audit` | 0 vulnerabilities in dependencies |

---

## Phase 9: Performance & Load

| # | Task | Validation Test |
|---|------|-----------------|
| 9.1 | Discovery endpoint p99 < 50ms | `k6` test: 10,000 RPS, p99 < 50ms |
| 9.2 | Token endpoint (client credentials) p99 < 100ms | `k6` test: 1,000 RPS, p99 < 100ms |
| 9.3 | UserInfo endpoint p99 < 50ms | `k6` test: 2,000 RPS, p99 < 50ms |
| 9.4 | API key verification p99 < 20ms | `k6` test: 5,000 RPS, p99 < 20ms |
| 9.5 | Memory stable under load | `heaptrack` or runtime metrics: no growth after 5 min load |
| 9.6 | PostgreSQL pool not exhausted | `max_connections` never hits limit under 2x expected load |
| 9.7 | WASM artifact size < 20MB | `ls -lh target/wasm32-wasip2/release/*.wasm` shows < 20MB |
| 9.8 | WASM startup time < 2s | `time wasmtime run ...` shows < 2s to first health response |
| 9.9 | **Gate**: Load test 5 minutes | All SLOs met; error rate < 0.1% |

---

## Phase 10: Deployment

| # | Task | Validation Test |
|---|------|-----------------|
| 10.1 | `D:\dev\Wasm-Cloud-Platform\oidc-hub\wasm\` contains `.wasm` | File exists and is non-empty |
| 10.2 | `D:\dev\Wasm-Cloud-Platform\oidc-hub\front\admin\dist\` built | `index.html` and `js/index.js` present |
| 10.3 | PostgreSQL running and accessible | `psql` connects with configured URL |
| 10.4 | Migrations applied | `SELECT version FROM schema_migrations` returns latest |
| 10.5 | Environment variables configured | `start-wasmtime.ps1` runs without missing env errors |
| 10.6 | `wasmtime run` starts server | `curl http://localhost:8080/health` returns 200 |
| 10.7 | Proxy gateway routes correctly | `https://auth.example.com/.well-known` returns discovery |
| 10.8 | TLS configured | SSL Labs test returns A+ |
| 10.9 | Rate limiting active | 11 rapid requests return 429 |
| 10.10 | Security headers present | `curl -I` shows `X-Frame-Options`, `HSTS` |
| 10.11 | Logging outputs JSON | Log line parses as valid JSON |
| 10.12 | Database backup scheduled | Daily `.dump` file created automatically |
| 10.13 | Rollback procedure tested | Previous `.wasm` restored; service resumes |
| 10.14 | **Gate**: Full E2E in production | Playwright tests pass against deployed URL |

---

## Final Sign-Off

- [ ] All 10 phases complete
- [ ] All validation tests pass
- [ ] Security audit passed
- [ ] Load tests meet SLOs
- [ ] Documentation complete (README, API docs, deployment guide)
- [ ] CI/CD pipeline green
- [ ] Team review approved
- [ ] **PRODUCTION READY**
