# Load Tests — OpenID Connect WASI Hub

k6 load testing scripts for validating Phase 9 SLOs against the OIDC Hub.

## SLO Targets (Master Checklist Phase 9)

| #   | SLO                                      | Target                          |
|-----|------------------------------------------|---------------------------------|
| 9.1 | Discovery endpoint p99                   | < 50 ms @ 10 000 RPS            |
| 9.2 | Token endpoint (client_credentials) p99 | < 100 ms @ 1 000 RPS            |
| 9.3 | UserInfo endpoint p99                    | < 50 ms @ 2 000 RPS             |
| 9.4 | API key verification p99                 | < 20 ms @ 5 000 RPS             |
| 9.5 | Memory stable under load                 | No growth after 5 min           |
| 9.6 | PostgreSQL pool not exhausted            | max_connections never hit at 2×  |
| 9.7 | WASM artifact size                       | < 20 MB                         |
| 9.8 | WASM startup time                        | < 2 s (time to first health OK)  |
| 9.9 | 5-minute load test                       | All SLOs met; error rate < 0.1%  |

## Install k6

```bash
# macOS
brew install k6

# Linux (Debian/Ubuntu)
sudo gpg -k
sudo gpg --no-default-keyring --keyring /usr/share/keyrings/k6-archive-keyring.gpg \
  --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys C5AD17C747E3415A36442D57C788647F8C296C60
echo "deb [signed-by=/usr/share/keyrings/k6-archive-keyring.gpg] https://dl.k6.io/deb stable main" \
  | sudo tee /etc/apt/sources.list.d/k6.list
sudo apt-get update
sudo apt-get install k6

# Windows
choco install k6
```

## Seed Test Data

Before running load tests, the following test data must exist in the database:

### 1. Admin User

The default admin user is created during initial migration. Verify it exists:

```sql
-- Check admin user exists in master realm
SELECT id, email FROM users WHERE email = 'admin@localhost' AND realm_id = (
  SELECT id FROM realms WHERE name = 'master'
);
```

If you need to create it manually:

```sql
-- Password hash for "admin123" using argon2id — generate with the app's hasher
INSERT INTO users (id, realm_id, email, password_hash, email_verified, enabled, created_at)
VALUES (
  gen_random_uuid(),
  (SELECT id FROM realms WHERE name = 'master'),
  'admin@localhost',
  '$argon2id$v=19$m=19456,t=2,p=1$...$...',
  true,
  true,
  now()
);
```

### 2. Service Client (for client_credentials)

Create a confidential client that allows the `client_credentials` grant:

```bash
# Using the admin API
curl -X POST http://localhost:8080/admin/clients \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer <admin-token>' \
  -d '{
    "realm_id": "<master-realm-id>",
    "client_id": "test-service-client",
    "client_type": "confidential",
    "client_secret": "test-service-secret",
    "name": "Load Test Service Client",
    "allowed_grant_types": ["client_credentials"],
    "allowed_scopes": ["openid"],
    "enabled": true
  }'
```

### 3. API Key

Create an API key with admin scope:

```bash
# Using the admin API
curl -X POST http://localhost:8080/api/keys \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer <admin-token>' \
  -d '{
    "realm_id": "<master-realm-id>",
    "name": "load-test-admin-key",
    "scopes": ["admin"],
    "expires_in_days": 1
  }'
```

The response will contain `raw_key` — use this as the `API_KEY` env var.

## Environment Variables

| Variable         | Default                          | Description                        |
|------------------|----------------------------------|------------------------------------|
| `BASE_URL`       | `http://localhost:8080`          | OIDC Hub base URL                  |
| `ADMIN_EMAIL`    | `admin@localhost`               | Admin user email                   |
| `ADMIN_PASSWORD` | `admin123`                       | Admin user password                |
| `CLIENT_ID`      | `test-service-client`           | Service client ID                  |
| `CLIENT_SECRET`  | `test-service-secret`            | Service client secret              |
| `API_KEY`        | `sk_test_admin_key_placeholder` | Raw API key for key verification   |
| `REALM_ID`       | `00000000-...-000000000001`      | Realm UUID for API key queries     |

## Run Individual Tests

```bash
# Smoke test (quick functional check)
k6 run load-tests/k6/smoke.js

# Discovery endpoint (SLO 9.1)
k6 run load-tests/k6/discovery.js

# Token endpoint (SLO 9.2)
k6 run -e CLIENT_ID=test-service-client -e CLIENT_SECRET=test-service-secret \
  load-tests/k6/token.js

# UserInfo endpoint (SLO 9.3)
k6 run load-tests/k6/userinfo.js

# API key verification (SLO 9.4)
k6 run -e API_KEY=sk_live_xxx -e REALM_ID=uuid \
  load-tests/k6/apikey.js
```

## Run Full 5-Minute Load Test (SLO 9.9)

```bash
k6 run \
  -e BASE_URL=http://localhost:8080 \
  -e CLIENT_ID=test-service-client \
  -e CLIENT_SECRET=test-service-secret \
  -e API_KEY=sk_live_xxx \
  -e REALM_ID=uuid \
  load-tests/k6/full-flow.js
```

This runs for 5 minutes with a mixed traffic profile:
- **40%** discovery requests (~4 000 RPS)
- **30%** token requests (~3 000 RPS)
- **20%** userinfo requests (~2 000 RPS)
- **10%** apikey requests (~1 000 RPS)

## Interpret Results

k6 prints a summary at the end of each run. Key sections:

### ✅ / ❌ Thresholds

Each threshold is marked as passed or failed:

```
✓ http_req_duration{name:discovery}... p(99) < 50 ms
✗ http_req_duration{name:apikey}...... p(99) < 20 ms
```

- **All ✅** → SLOs are met.
- **Any ❗** → The corresponding SLO is violated. Investigate before releasing.

### Error Rate

```
http_req_failed................: 0.03%  ✓ rate < 0.001
```

For SLO 9.9, the overall error rate must be below **0.1%**.

### Request Rate

```
http_reqs..............: 123456  2057.6/s
```

Verify the achieved RPS meets or exceeds the target for each scenario.

### Latency Percentiles

```
http_req_duration:
  avg=5.2ms   p(90)=8.1ms   p(95)=12.3ms   p(99)=42.1ms
```

Focus on **p(99)** — this is the SLO metric.

## Additional Checks (Non-k6)

### 9.5 — Memory Stability

Run the full-flow test and monitor the WASM process memory:

```bash
# In a separate terminal, monitor RSS every 5 seconds
watch -n 5 "ps -o pid,rss,vsz,comm -p $(pgrep -f openid_connect_wasi)"
```

Memory should plateau and not grow after the initial 5-minute warm-up.

### 9.6 — PostgreSQL Pool

Check `pg_stat_activity` during the 2× load test:

```sql
SELECT count(*) AS active_connections,
       (SELECT setting::int FROM pg_settings WHERE name = 'max_connections') AS max_connections
FROM pg_stat_activity
WHERE datname = current_database();
```

`active_connections` must never reach `max_connections`.

### 9.7 — WASM Artifact Size

```bash
ls -lh target/wasm32-wasip2/release/openid_connect_wasi.wasm
```

Must be < 20 MB.

### 9.8 — WASM Startup Time

```bash
time sh -c 'wasmtime run --wasi inherit-network --wasi inherit-env \
  target/wasm32-wasip2/release/openid_connect_wasi.wasm & \
  until curl -s http://localhost:8080/health > /dev/null; do sleep 0.1; done'
```

Must be < 2 seconds to first health response.

## Directory Layout

```
load-tests/
├── README.md           ← you are here
└── k6/
    ├── lib/
    │   └── helpers.js  ← shared config, thresholds, auth helpers
    ├── smoke.js        ← 1 VU functional smoke test
    ├── discovery.js    ← SLO 9.1 — discovery endpoint
    ├── token.js        ← SLO 9.2 — token endpoint
    ├── userinfo.js     ← SLO 9.3 — userinfo endpoint
    ├── apikey.js       ← SLO 9.4 — API key verification
    └── full-flow.js    ← SLO 9.9 — 5-min mixed load test
```
