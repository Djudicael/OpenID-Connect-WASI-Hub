# Security Scanning — OWASP ZAP Baseline

This directory contains tooling for automated security scanning of the OIDC Hub using **OWASP ZAP** (Zed Attack Proxy).

## What is ZAP Baseline Scan?

The ZAP baseline scan is a **passive, non-invasive** security scan. It:

- ✅ **Does check for**: Missing security headers, insecure cookies, mixed content, information leakage, outdated TLS configuration, misconfigured CORS, and other passive observations
- ❌ **Does NOT do**: SQL injection, XSS, CSRF, brute force, or any active attacks against the server

The baseline scan is safe to run against production systems — it only observes, never attacks.

## Quick Start

### Prerequisites

- Docker installed and running
- OIDC Hub server running and accessible

### Run the Scan

```bash
# Default: scans http://localhost:8080 for 5 minutes
./security/zap-baseline.sh

# Custom target and duration
./security/zap-baseline.sh --target https://staging.example.com --duration 10

# Also generate JSON report
./security/zap-baseline.sh --json

# Custom report location
./security/zap-baseline.sh --report ./my-report.html
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `ZAP_TARGET_URL` | Target URL override | `http://localhost:8080` |
| `ZAP_API_KEY` | ZAP API key (daemon mode) | *(none)* |
| `ZAP_DOCKER_IMAGE` | ZAP Docker image | `owasp/zap2docker-stable` |

## Endpoints Scanned

The baseline scan tests the following OIDC Hub endpoints:

| Endpoint | Description |
|----------|-------------|
| `/.well-known/openid-configuration` | OIDC discovery document |
| `/oidc/jwks` | JSON Web Key Set |
| `/oidc/authorize` | Authorization endpoint |
| `/oidc/token` | Token endpoint |
| `/oidc/userinfo` | UserInfo endpoint |
| `/oidc/introspect` | Token introspection |
| `/oidc/revoke` | Token revocation |
| `/api/keys` | API key management |
| `/health` | Health check |
| `/health/ready` | Readiness check |

## Interpreting Results

### ZAP Exit Codes

| Code | Meaning | Build Impact |
|------|---------|-------------|
| 0 | No alerts found | ✅ Pass |
| 1 | WARN-level alerts (informational) | ✅ Pass (review recommended) |
| 2 | HIGH or CRITICAL alerts found | ❌ Fail |
| 3 | ZAP error (scan didn't complete) | ❌ Fail |

### Report Formats

- **HTML** (`zap-report.html`) — Human-readable report with alert details, URLs, and evidence
- **JSON** (`zap-report.json`) — Machine-readable format for CI integration and trend analysis

### Alert Severity Levels

| Level | Description | Build Impact |
|-------|-------------|-------------|
| Informational | Best practice observations | No impact |
| Low | Minor issues | No impact |
| Medium | Moderate risk | Review recommended |
| High | Significant security risk | ❌ Build fails |
| Critical | Severe vulnerability | ❌ Build fails |

## Configuring Alert Thresholds

The `zap-config.conf` file controls how each alert rule is handled:

```
# Format: <rule-id> IGNORE|WARN|FAIL <description>
10040 IGNORE (Cookie Without Secure Flag) - Expected on localhost
10020 FAIL  (X-Frame-Options Header Not Set)
```

### Threshold Levels

- **IGNORE** — Suppress the alert entirely. Use only for confirmed false positives.
- **WARN** — Report the alert but don't fail the build. Use for informational items.
- **FAIL** — Fail the build if this alert is triggered. Use for security-critical checks.

### Finding Rule IDs

1. Run a scan and check the HTML report for the alert
2. The rule ID is shown in the alert details (e.g., "CWE-1021" or "WASC-15")
3. Look up the ZAP rule ID at: https://www.zaproxy.org/docs/alerts/

## Adding Exceptions for False Positives

When ZAP reports an alert that is a confirmed false positive for your environment:

1. Identify the rule ID from the report
2. Add an entry to `zap-config.conf`:

```bash
# Example: Ignore missing Secure flag on localhost
10040 IGNORE (Cookie Without Secure Flag) - Expected on localhost without TLS
```

3. Add a comment explaining **why** it's a false positive
4. Re-run the scan to verify the exception works

> ⚠️ **Warning**: Only add IGNORE rules for confirmed false positives. Never suppress real security issues.

### Common False Positives for OIDC

| Rule | Reason | Exception |
|------|--------|-----------|
| Cookie without Secure flag | Expected on localhost (no TLS) | IGNORE in dev, FAIL in prod |
| Content-Type missing | OIDC error responses may omit header | WARN |
| CSP not set | CSP is complex for OIDC flows | WARN (review manually) |

## Cloud Build Integration

### Running as a Separate Pipeline

The ZAP scan runs as a **separate** Cloud Build pipeline (not in the main build) because:

1. Security scans take 5-10 minutes
2. They require a running server
3. They should not block the main CI/CD pipeline

### Running the Security Pipeline

```bash
# Scan staging environment
gcloud builds submit --config=security/zap-baseline.yaml \
  --substitutions=_TARGET_URL=https://staging.example.com

# Scan with custom duration
gcloud builds submit --config=security/zap-baseline.yaml \
  --substitutions=_TARGET_URL=https://staging.example.com,_SCAN_DURATION=10
```

### Substitutions

| Variable | Description | Default |
|----------|-------------|---------|
| `_BUCKET_NAME` | GCS bucket for reports | `openid-connect-wasi-security-reports` |
| `_TARGET_URL` | Target URL to scan | `http://localhost:8080` |
| `_ZAP_IMAGE` | ZAP Docker image | `owasp/zap2docker-stable` |
| `_SCAN_DURATION` | Scan duration (minutes) | `5` |

### Report Storage

Reports are uploaded to GCS:

```
gs://<bucket>/zap-scans/<timestamp>-<build-id>/zap-report.html
gs://<bucket>/zap-scans/<timestamp>-<build-id>/zap-report.json
gs://<bucket>/zap-scans/latest/zap-report.html  (always the latest)
gs://<bucket>/zap-scans/latest/zap-report.json
```

### Scheduled Scans

For production security monitoring, set up a scheduled Cloud Build trigger:

```bash
# Create a scheduled scan (daily at 2 AM UTC)
gcloud scheduler jobs create http zap-daily-scan \
  --schedule="0 2 * * *" \
  --uri="https://cloudbuild.googleapis.com/v1/projects/<PROJECT>/builds" \
  --http-method=POST \
  --oauth-service-account-email="<SA>@<PROJECT>.iam.gserviceaccount.com"
```

## What the Baseline Scan Covers

### Security Headers

- `X-Frame-Options` — Prevents clickjacking
- `X-Content-Type-Options` — Prevents MIME-type sniffing
- `Strict-Transport-Security` — Enforces HTTPS
- `Content-Security-Policy` — Controls resource loading
- `X-XSS-Protection` — Browser XSS filter

### Cookie Security

- `Secure` flag — Only sent over HTTPS
- `HttpOnly` flag — Not accessible from JavaScript
- `SameSite` attribute — CSRF protection

### Information Leakage

- Server version headers
- Stack traces in error responses
- Debug information exposure
- Directory listing

### TLS Configuration

- Weak cipher suites
- Outdated protocol versions
- Certificate validity

## What the Baseline Scan Does NOT Cover

The baseline scan is passive only. For comprehensive security testing, consider:

| What | Tool | When |
|------|------|------|
| SQL injection | ZAP active scan | Pre-release |
| XSS testing | ZAP active scan | Pre-release |
| CSRF testing | ZAP active scan | Pre-release |
| Fuzzing | ZAP fuzzer | Pre-release |
| Dependency audit | `cargo audit` / `cargo deny` | Every build (in main CI) |
| Penetration testing | Manual + professional tools | Before production launch |

## Protocol-negative and log-redaction gate

The ZAP baseline does not replace focused OpenID Connect protocol tests. Run the
following in Linux or WSL before promoting a backend artifact:

```bash
export CARGO_TARGET_DIR=/tmp/openid-connect-wasi-target
cargo test -p integration-tests security_tests:: -- --test-threads=1
cargo test -p openid-connect-wasi middleware::logging::tests
cargo clippy -p oidc-oidc -p openid-connect-wasi -p integration-tests \
  --all-targets -- -D warnings
cargo build -p openid-connect-wasi --target wasm32-wasip2 --release
```

Required behavior:

- validate the client and exact registered redirect URI before using a caller
  redirect for either success or error delivery;
- reject replayed and expired authorization codes and expired login sessions;
- bind nonce to the authorization transaction and returned ID token;
- log request paths, never complete URIs containing `code`, `state`, `nonce`,
  `request`, or other query values; and
- never log authorization/cookie headers, passwords, tokens, client secrets, or
  database URLs.

`state` belongs to the relying party: the authorization server echoes the opaque
value, while the RP must reject mismatch. A nonce is checked against the ID token
and is not an independently expiring server-side credential. Validate RP state
mismatch, ID-token nonce mismatch, and clock skew in the real client integration.

The API-key timing regression compares two invalid secrets with the same stored
lookup prefix and mismatches at opposite ends. Do not compare a valid endpoint
request with an invalid one: a valid request performs usage accounting and the
protected operation, so that measures authorization outcome work rather than
constant-time hash verification.

The development seed commands print disposable local credentials. They must not
run in production automation. Production bootstrap must retrieve secrets from
the approved secret system and must not print them.

### Running an Active Scan (Advanced)

> ⚠️ **Warning**: Active scans send attack payloads. Only run against test/staging environments, never production.

```bash
# Active scan (NOT the baseline — this attacks the server)
docker run --rm --network host owasp/zap2docker-stable \
  zap-active-scan.py \
  -t http://localhost:8080 \
  -c /zap/config/zap-config.conf
```

## Troubleshooting

### "Target not reachable"

- Ensure the OIDC server is running: `curl http://localhost:8080/health`
- Check Docker networking: `--network host` is required for localhost access
- On macOS, `host.docker.internal` may be needed instead of `localhost`

### "ZAP container exits immediately"

- Check Docker logs: `docker logs zap-baseline-oidc-*`
- Ensure sufficient memory (ZAP needs ~1GB)
- Try increasing the scan duration

### "Too many false positives"

- Review and update `zap-config.conf`
- Add IGNORE rules for confirmed false positives
- Document the reason for each exception

### "Scan takes too long"

- Reduce `--duration` (minimum recommended: 3 minutes)
- The first run pulls the Docker image (~500MB), subsequent runs are faster

## Files

| File | Description |
|------|-------------|
| `zap-baseline.sh` | Main scan script (run this) |
| `zap-config.conf` | Alert thresholds and exceptions |
| `zap-baseline.yaml` | Cloud Build pipeline definition |
| `README.md` | This documentation |
