# Deployment Plan — Wasm-Cloud-Platform

Target deployment directory: `D:\dev\Wasm-Cloud-Platform`

---

## 1. Deployment Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           Proxy API Gateway                              │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐ │
│  │   TLS       │  │   Rate      │  │  API Key    │  │   Route to      │ │
│  │ Termination │  │   Limit     │  │  Validation │  │   WASM Host     │ │
│  │  (443)      │  │   (Token)   │  │   (Edge)    │  │   (8080)        │ │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────────┘ │
└─────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                        WASM Component Host                               │
│  ┌─────────────────────────────────────────────────────────────────────┐│
│  │              wasmtime / WasmEdge / wamr                             ││
│  │  ┌───────────────────────────────────────────────────────────────┐  ││
│  │  │          openid_connect_wasi.wasm                              │  ││
│  │  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ │  ││
│  │  │  │  OIDC   │ │ API Key │ │  Admin  │ │ Health  │ │  ││
│  │  │  │ Router  │ │ Router  │ │ Static  │ │ Router  │ │  ││
│  │  │  └─────────┘ └─────────┘ └─────────┘ └─────────┘ │  ││
│  │  └───────────────────────────────────────────────────────────────┘  ││
│  └─────────────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         PostgreSQL Database                              │
│  (Pre-migrated schema, connection pool max 5 for WASM, backups daily)   │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Artifact Build

### Backend WASM
```bash
# Release build
cargo build --target wasm32-wasip2 --release

# Strip symbols (optional, for smaller size)
wasm-strip target/wasm32-wasip2/release/openid_connect_wasi.wasm

# Compress
wasm-opt -Oz -o openid_connect_wasi.opt.wasm target/wasm32-wasip2/release/openid_connect_wasi.wasm
```

### Frontend
```bash
cd front/admin
npm ci
npm run build
# Output: front/admin/dist/ (static files)
```

---

## 3. Directory Structure in `D:\dev\Wasm-Cloud-Platform`

```
D:\dev\Wasm-Cloud-Platform\
├── oidc-hub\
│   ├── wasm\
│   │   └── openid_connect_wasi.wasm      # Main component
│   ├── front\
│   │   └── admin\                        # Built static files
│   │       ├── index.html
│   │       ├── js/
│   │       ├── style/
│   │       └── ressource/
│   ├── config\
│   │   └── oidc.toml                     # Runtime config
│   ├── ssl\
│   │   ├── cert.pem                      # TLS cert (or use gateway)
│   │   └── key.pem
│   └── scripts\
│       ├── start-wasmtime.ps1
│       ├── start-wasmedge.ps1
│       └── migrate.ps1                   # Native migration runner
├── proxy-gateway\
│   └── nginx.conf / traefik.yml          # Gateway config
└── docker-compose.yml                    # Optional: PG + gateway + wasm
```

---

## 4. Runtime Configuration

### Environment Variables
```powershell
# Database
$env:OIDC_DATABASE_URL = "postgresql://oidc:secret@localhost:5432/oidc_hub"

# Server
$env:OIDC_SERVER_BIND_ADDRESS = "0.0.0.0"
$env:OIDC_SERVER_PORT = "8080"

# Security
$env:OIDC_ENCRYPTION_KEY = "64-hex-characters"
$env:OIDC_SIGNING_KEY_PEM = "-----BEGIN PRIVATE KEY-----..."

# Features
$env:OIDC_LOG_LEVEL = "info"
```

### Config File (`config/oidc.toml`)
```toml
[server]
bind_address = "0.0.0.0"
port = 8080

[database]
url = "postgresql://oidc:secret@localhost:5432/oidc_hub"
max_connections = 5

[security]
encryption_key = "${OIDC_ENCRYPTION_KEY}"
signing_key_pem = "${OIDC_SIGNING_KEY_PEM}"

[logging]
format = "json"
level = "info"
```

---

## 5. Startup Scripts

### PowerShell (Windows — Primary Target)
```powershell
# start-wasmtime.ps1
$ErrorActionPreference = "Stop"

$env:OIDC_DATABASE_URL = "postgresql://oidc:${env:PG_PASSWORD}@localhost:5432/oidc_hub"
$wasmPath = "$PSScriptRoot\..\wasm\openid_connect_wasi.wasm"

# Optional: run migrations first (native binary)
& "$PSScriptRoot\migrate.ps1"

# Start WASM component
wasmtime run `
  --wasi inherit-network `
  --wasi inherit-env `
  --wasi allow-ip-name-lookup `
  --env OIDC_DATABASE_URL=$env:OIDC_DATABASE_URL `
  --env OIDC_SERVER_PORT=$env:OIDC_SERVER_PORT `
  --env OIDC_ENCRYPTION_KEY=$env:OIDC_ENCRYPTION_KEY `
  --env OIDC_SIGNING_KEY_PEM=$env:OIDC_SIGNING_KEY_PEM `
  --listenfd `
  $wasmPath
```

### wasmtime serve (HTTP Server Mode)
```powershell
wasmtime serve `
  --addr 127.0.0.1:8080 `
  --wasi inherit-env `
  $wasmPath
```

---

## 6. Proxy Gateway Configuration

### Nginx
```nginx
upstream oidc_wasm {
    server 127.0.0.1:8080;
    keepalive 32;
}

server {
    listen 443 ssl http2;
    server_name auth.example.com;

    ssl_certificate /etc/ssl/certs/auth.example.com.crt;
    ssl_certificate_key /etc/ssl/private/auth.example.com.key;

    # Security headers
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Strict-Transport-Security "max-age=31536000" always;

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=oidc:10m rate=10r/s;
    limit_req zone=oidc burst=20 nodelay;

    # Static admin UI
    location /admin/ {
        alias D:/dev/Wasm-Cloud-Platform/oidc-hub/front/admin/dist/;
        try_files $uri $uri/ /admin/index.html;
    }

    # OIDC & API routes
    location ~ ^/(oidc|api|\.well-known)/ {
        proxy_pass http://oidc_wasm;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 30s;
    }

    # Health check
    location /health {
        proxy_pass http://oidc_wasm;
        access_log off;
    }
}
```

### Traefik (Alternative)
```yaml
http:
  routers:
    oidc:
      rule: "Host(`auth.example.com`)"
      service: oidc-wasm
      tls: {}
      middlewares:
        - rate-limit
        - security-headers
  services:
    oidc-wasm:
      loadBalancer:
        servers:
          - url: "http://localhost:8080"
  middlewares:
    rate-limit:
      rateLimit:
        average: 100
        burst: 50
    security-headers:
      headers:
        customResponseHeaders:
          X-Frame-Options: "DENY"
```

---

## 7. Database Setup

### PostgreSQL Setup (Docker)
```yaml
# docker-compose.yml
version: "3.8"
services:
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_USER: oidc
      POSTGRES_PASSWORD: ${PG_PASSWORD}
      POSTGRES_DB: oidc_hub
    volumes:
      - pgdata:/var/lib/postgresql/data
      - ./migrations/postgresql:/docker-entrypoint-initdb.d
    ports:
      - "5432:5432"
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U oidc"]
      interval: 5s
      timeout: 5s
      retries: 5

  oidc-wasm:
    image: wasmtime:latest
    command: >
      serve
      --addr 0.0.0.0:8080
      --wasi inherit-network
      --wasi inherit-env
      /wasm/openid_connect_wasi.wasm
    volumes:
      - ./oidc-hub/wasm:/wasm:ro
    environment:
      OIDC_DATABASE_URL: postgresql://oidc:${PG_PASSWORD}@postgres:5432/oidc_hub
      OIDC_SERVER_PORT: "8080"
    depends_on:
      postgres:
        condition: service_healthy
    ports:
      - "8080:8080"

volumes:
  pgdata:
```

---

## 8. Health & Monitoring

### Health Endpoints
- `GET /health` → `{"status":"ok","version":"0.1.0"}`
- `GET /health/ready` → Checks DB connectivity
- `GET /health/live` → Always 200 (liveness probe)

### Metrics (Prometheus)
- `GET /metrics` → Custom metrics (if supported by runtime)
- Otherwise: structured logs → Loki / Fluent Bit

### Log Aggregation
```json
{
  "timestamp": "2025-05-07T12:00:00Z",
  "level": "INFO",
  "trace_id": "uuid",
  "message": "token issued",
  "realm_id": "uuid",
  "client_id": "my-app",
  "user_id": "uuid",
  "duration_ms": 12
}
```

---

## 9. Backup & Recovery

### Database
```powershell
# Daily backup
pg_dump -h localhost -U oidc -Fc oidc_hub > D:\Backups\oidc_hub_%date%.dump

# Restore
pg_restore -h localhost -U oidc -d oidc_hub D:\Backups\oidc_hub_2025-05-07.dump
```

### Signing Keys
- Store in PostgreSQL (`signing_keys` table).
- Encrypted private keys using `OIDC_ENCRYPTION_KEY`.
- Export public keys via JWKS endpoint.

---

## 10. Rolling Updates

1. Build new WASM artifact.
2. Run migrations (native, backward-compatible).
3. Deploy new artifact to `wasm/` directory.
4. Restart `wasmtime` process (graceful: drain connections).
5. Verify `/health/ready` returns 200.
6. Rollback: restore previous `.wasm` file, restart.

---

## 11. Checklist

- [ ] `D:\dev\Wasm-Cloud-Platform\oidc-hub\wasm\` contains `.wasm` artifact
- [ ] `D:\dev\Wasm-Cloud-Platform\oidc-hub\front\admin\dist\` contains built UI
- [ ] PostgreSQL running and accessible
- [ ] Migrations applied (schema version matches app version)
- [ ] Environment variables set (`OIDC_DATABASE_URL`, `OIDC_ENCRYPTION_KEY`, etc.)
- [ ] `start-wasmtime.ps1` starts without errors
- [ ] Health endpoint responds at `http://localhost:8080/health`
- [ ] Discovery document available at `/.well-known/openid-configuration`
- [ ] Admin UI served at `/admin/`
- [ ] TLS configured on proxy gateway
- [ ] Rate limiting active
- [ ] Security headers present (`X-Frame-Options`, `HSTS`)
- [ ] Logging outputs structured JSON
- [ ] Database backups scheduled and tested
- [ ] Rollback procedure documented and tested
- [ ] CI/CD pipeline deploys to `Wasm-Cloud-Platform` on merge to main
