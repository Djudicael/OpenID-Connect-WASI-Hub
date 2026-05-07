# Testing & Validation Strategy

Production-grade quality gates for every layer: unit, integration, security, load, and WASM runtime tests.

---

## 1. Test Pyramid

```
       ^
      / \
     / E2E \           Playwright (admin UI flows)
    /-------\
   /         \
  / Integration \      Native + WASM runtime against real PostgreSQL
 /---------------\
/                 \
/     Unit Tests    \  Per-crate, no I/O, mocked traits
---------------------
```

Target coverage:
- **Unit**: >= 80% line coverage
- **Integration**: All endpoints hit at least once
- **E2E**: Critical user journeys (login, create key, create MLS group)

---

## 2. Unit Tests

### Location
```
crates/<name>/src/*.rs        # Source
crates/<name>/src/tests/      # Unit tests (inline modules)
```

### Pattern
```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_password_hashing() {
        let hasher = Argon2Hasher::default();
        let hash = hasher.hash("password123").unwrap();
        assert!(hasher.verify("password123", &hash).unwrap());
        assert!(!hasher.verify("wrong", &hash).unwrap());
    }
    
    #[test]
    fn test_token_expiry() {
        let clock = MockClock::at(1000);
        let token = AccessToken::new(clock.now(), Duration::from_secs(900));
        assert!(!token.is_expired(&clock));
        
        clock.advance(Duration::from_secs(901));
        assert!(token.is_expired(&clock));
    }
}
```

### Mocking Strategy
- `Clock` trait -> `MockClock` (deterministic time)
- `Repository` trait -> `InMemoryRepository` (HashMap backend)
- `TokenService` trait -> `MockTokenService` (predictable JWTs)
- `Hasher` trait -> `FastHasher` (fast hashes for tests, NOT production)

**Validation Criteria**:
- [ ] `cargo test -p oidc-core` runs in < 5 seconds
- [ ] All external I/O mocked (no real network, no real DB)
- [ ] Deterministic: same seed -> same results
- [ ] Property-based tests for parsers (`proptest`)

---

## 3. Integration Tests

### Location
```
tests/integration/
├── Cargo.toml
├── src/
│   ├── main.rs
│   ├── helpers/
│   │   ├── mod.rs
│   │   ├── app.rs          # Spawn native server on random port
│   │   ├── db.rs           # Setup/teardown test database
│   │   └── fixtures.rs     # Pre-loaded test data
│   ├── oidc_flows.rs
│   ├── apikey_flows.rs
│   ├── mls_flows.rs
│   └── health.rs
```

### Native Server Helper
```rust
pub async fn spawn_app() -> TestApp {
    let db = setup_test_db().await; // Creates `oidc_test_<random>` database
    let config = TestConfig::from_db(&db);
    let state = AppState::from_config(config).await;
    let router = app_router(state);
    
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    
    TestApp { port, db }
}
```

### Example: Authorization Code Flow
```rust
#[tokio::test]
async fn authorization_code_flow_with_pkce() {
    let app = spawn_app().await;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    
    // 1. Get authorize redirect
    let (verifier, challenge) = generate_pkce();
    let resp = client
        .get(format!("http://localhost:{}/oidc/authorize", app.port))
        .query(&[...])
        .send()
        .await;
    assert_eq!(resp.status(), 302);
    let location = resp.headers().get("location").unwrap();
    let code = extract_code(location);
    
    // 2. Exchange code for tokens
    let resp = client
        .post(format!("http://localhost:{}/oidc/token", app.port))
        .form(&[...])
        .send()
        .await;
    assert_eq!(resp.status(), 200);
    
    let tokens: TokenResponse = resp.json().await.unwrap();
    assert!(tokens.access_token.len() > 0);
    assert!(tokens.id_token.len() > 0);
    assert!(tokens.refresh_token.len() > 0);
    
    // 3. Introspect
    let resp = client
        .post(format!("http://localhost:{}/oidc/introspect", app.port))
        .basic_auth("client_id", Some("client_secret"))
        .form(&[("token", &tokens.access_token)])
        .send()
        .await;
    let info: IntrospectionResponse = resp.json().await.unwrap();
    assert!(info.active);
    
    // 4. UserInfo
    let resp = client
        .get(format!("http://localhost:{}/oidc/userinfo", app.port))
        .bearer_auth(&tokens.access_token)
        .send()
        .await;
    assert_eq!(resp.status(), 200);
    
    // 5. Revoke
    let resp = client
        .post(format!("http://localhost:{}/oidc/revoke", app.port))
        .basic_auth("client_id", Some("client_secret"))
        .form(&[("token", &tokens.access_token)])
        .send()
        .await;
    assert_eq!(resp.status(), 200);
    
    // 6. Verify inactive
    let resp = client
        .post(format!("http://localhost:{}/oidc/introspect", app.port))
        .basic_auth("client_id", Some("client_secret"))
        .form(&[("token", &tokens.access_token)])
        .send()
        .await;
    let info: IntrospectionResponse = resp.json().await.unwrap();
    assert!(!info.active);
}
```

**Validation Criteria**:
- [ ] `cargo test --test integration` passes against PostgreSQL 15
- [ ] Each OIDC flow tested end-to-end
- [ ] API key create -> verify -> revoke tested
- [ ] MLS group create -> join -> commit tested
- [ ] Tests run in < 60 seconds total
- [ ] Parallel test execution safe (unique DB per test)

---

## 4. WASM Runtime Tests

### Approach
Build the WASM component and run it under `wasmtime`, hitting endpoints via HTTP.

```bash
# CI script
#!/bin/bash
set -e

cargo build --target wasm32-wasip2 --release

# Start wasmtime in background
wasmtime run \
  --wasi inherit-network \
  --wasi inherit-env \
  --env OIDC_DATABASE_URL=postgresql://localhost/oidc_test \
  target/wasm32-wasip2/release/openid_connect_wasi.wasm &
WASM_PID=$!
sleep 2

# Run integration tests pointing at wasmtime port
cargo test --test wasm_integration -- --test-threads=1

kill $WASM_PID
```

### WASM-Specific Tests
- [ ] Health endpoint responds
- [ ] OIDC discovery returns valid JSON
- [ ] Authorization code flow completes
- [ ] API key middleware accepts valid key
- [ ] MLS KeyPackage upload succeeds
- [ ] Memory usage < 128MB after 100 requests

---

## 5. Security Tests

### Static Analysis
| Tool | Command | Checks |
|------|---------|--------|
| `cargo-audit` | `cargo audit` | Known CVEs in dependencies |
| `cargo-deny` | `cargo deny check` | License compliance, banned crates |
| `semgrep` | `semgrep --config=auto` | OWASP patterns |

### Fuzzing
```
crates/oidc-oidc/fuzz/
crates/oidc-mls/fuzz/
```
- Fuzz JWT parser with random bytes
- Fuzz MLS commit deserialization
- Fuzz OIDC query parameter parsing

### Penetration Test Scenarios
- [ ] SQL injection via all user inputs (parameterized queries prevent this; verify)
- [ ] OAuth2 redirect URI validation (exact match, no open redirect)
- [ ] PKCE bypass (public clients without PKCE rejected)
- [ ] Refresh token replay (reuse detection revokes family)
- [ ] Timing attacks on API key comparison (constant-time verify)
- [ ] JWT algorithm confusion (`alg: none` rejected)
- [ ] Session fixation (new session ID after login)
- [ ] Brute force: rate limiting on token endpoint (10 req/min per IP)

---

## 6. Load Tests

### Tool: `k6` or `oha`

```javascript
// load-test.js (k6)
import http from 'k6/http';
import { check } from 'k6';

export const options = {
  stages: [
    { duration: '1m', target: 100 },   // Ramp up
    { duration: '3m', target: 100 },   // Steady state
    { duration: '1m', target: 0 },     // Ramp down
  ],
};

export default function () {
  const res = http.get('http://localhost:8080/.well-known/openid-configuration');
  check(res, {
    'status is 200': (r) => r.status === 200,
    'response time < 100ms': (r) => r.timings.duration < 100,
  });
}
```

### Targets
| Endpoint | Target RPS | p99 Latency |
|----------|-----------|-------------|
| Discovery | 10,000 | 50ms |
| Token (client credentials) | 1,000 | 100ms |
| Token (auth code) | 500 | 150ms |
| UserInfo | 2,000 | 50ms |
| API Key Verify | 5,000 | 20ms |
| MLS Commit | 100 | 200ms |

---

## 7. Frontend Tests

### Unit (Component)
```javascript
// Using Web Test Runner + @open-wc/testing
import { expect } from '@open-wc/testing';
import '../app/components/ui/button.js';

describe('c-button', () => {
  it('renders label', async () => {
    const el = document.createElement('c-button');
    el.label = 'Click me';
    document.body.appendChild(el);
    expect(el.shadowRoot.textContent).to.include('Click me');
  });
});
```

### E2E (Playwright)
```javascript
// tests/e2e/login.spec.js
import { test, expect } from '@playwright/test';

test('admin login flow', async ({ page }) => {
  await page.goto('http://localhost:3008/login');
  await page.fill('[name="username"]', 'admin');
  await page.fill('[name="password"]', 'password');
  await page.click('button[type="submit"]');
  await expect(page).toHaveURL('http://localhost:3008/');
  await expect(page.locator('h1')).toContainText('Dashboard');
});
```

**Validation Criteria**:
- [ ] All critical paths covered: login, create API key, create MLS group
- [ ] Cross-browser: Chromium, Firefox, WebKit
- [ ] Mobile viewport test (admin UI responsive)

---

## 8. CI/CD Pipeline

```yaml
# .github/workflows/ci.yml
name: CI
on: [push, pull_request]

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo fmt -- --check
      - run: cargo clippy --all-targets --all-features -- -D warnings
      - run: cargo audit

  test-native:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:15
        env:
          POSTGRES_PASSWORD: postgres
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo test --workspace
        env:
          TEST_DATABASE_URL: postgresql://postgres:postgres@localhost/postgres

  build-wasm:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          targets: wasm32-wasip2
      - run: cargo build --target wasm32-wasip2 --release

  test-wasm:
    runs-on: ubuntu-latest
    needs: build-wasm
    services:
      postgres:
        image: postgres:15
        env:
          POSTGRES_PASSWORD: postgres
    steps:
      - uses: actions/checkout@v4
      - uses: bytecodealliance/actions/wasmtime-setup@v1
      - run: |
          wasmtime run --wasi inherit-network target/wasm32-wasip2/release/openid_connect_wasi.wasm &
          sleep 3
          cargo test --test wasm_integration

  test-frontend:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
      - run: cd front/admin && npm ci && npm run build
      - run: cd front/admin && npx playwright install && npx playwright test
```

---

## 9. Checklist

- [ ] Unit tests for `oidc-core` models and traits
- [ ] Mock implementations for all external dependencies
- [ ] Integration tests for all OIDC endpoints
- [ ] Integration tests for API key CRUD and verification
- [ ] Integration tests for MLS group lifecycle
- [ ] WASM build produces valid `.wasm` artifact
- [ ] WASM runtime tests pass under `wasmtime`
- [ ] `cargo audit` passes with zero vulnerabilities
- [ ] `cargo clippy` passes with zero warnings
- [ ] `cargo deny` passes license check
- [ ] Fuzz tests for JWT and MLS parsers
- [ ] Penetration test scenarios documented and automated where possible
- [ ] Load test meets RPS and latency targets
- [ ] Frontend component tests pass
- [ ] Frontend E2E tests pass (Playwright)
