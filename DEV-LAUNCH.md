# Dev Environment — `oidc-dev` & `oidc-wasm-dev`

The project provides **two** development orchestrators:

| Crate | Runtime | Use Case |
|-------|---------|----------|
| `oidc-dev` | Native (`cargo run`) | Full stack with frontend dev server + proxy |
| `oidc-wasm-dev` | WASM (`wasmtime serve`) | Test the exact WASM artifact that deploys to production |

Both handle PostgreSQL container lifecycle, migrations, and seed data automatically.

## Prerequisites (WSL)

```bash
# Podman (for PostgreSQL container)
sudo apt-get update && sudo apt-get install -y podman

# Node.js (for frontend build + proxy — oidc-dev only)
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
sudo apt-get install -y nodejs

# wasmtime (for oidc-wasm-dev)
curl https://wasmtime.dev/install.sh -sSf | bash

# Rust (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup target add wasm32-wasip2
```

---

## Option A: `oidc-dev` (Native)

Best for day-to-day frontend/backend development with hot reload.

```bash
cd openid_connect_wasi

# Start everything (DB + migrations + seed data + backend + frontend + proxy)
cargo run -p oidc-dev -- start

# Check status
cargo run -p oidc-dev -- status

# Start only the database (for running tests manually)
cargo run -p oidc-dev -- db-only

# Stop everything
cargo run -p oidc-dev -- stop
```

### Architecture

```
Browser → Proxy (port 3000) → Backend (port 8080)  /api/*, /oidc/*, /.well-known/*, /health
                      ↘ Frontend (port 3008)  /* (SPA fallback)
```

The proxy eliminates CORS issues by serving both frontend and backend from the same origin.

### URLs

| Service | URL | Description |
|---------|-----|-------------|
| **Proxy (use this)** | http://localhost:3000 | Single entrypoint — open in browser |
| Backend API | http://localhost:8080 | Direct backend access |
| Frontend dev | http://localhost:3008 | Direct frontend access |
| OIDC Discovery | http://localhost:3000/.well-known/openid-configuration | OIDC metadata |

---

## Option B: `oidc-wasm-dev` (WASI Preview 2 + JAMstack)

Best for testing the **exact production deployment**: WASM backend + pre-built static frontend served by a proxy. This mimics how you would deploy with a CDN (static files) + edge runtime (WASM).

```bash
cd openid_connect_wasi

# Start DB + build WASM + build frontend + proxy
cargo run -p oidc-wasm-dev -- start

# Run smoke tests against the running proxy (frontend + backend)
cargo run -p oidc-wasm-dev -- test

# Check status
cargo run -p oidc-wasm-dev -- status

# Stop everything
cargo run -p oidc-wasm-dev -- stop
```

### Architecture

```
Browser → Proxy (port 3000) → Backend (wasmtime serve, auto port)  /api/*, /oidc/*, /.well-known/*, /health, /realms/*
                      ↘ Static files (front/admin/dist/)  /* (SPA fallback)
                              ↓
                        WASM component (openid_connect_wasi.wasm)
                              ↓
                        PostgreSQL container
```

### URLs

| Service | URL | Description |
|---------|-----|-------------|
| **Proxy (use this)** | http://localhost:3000 | Single entrypoint — open in browser |
| Backend API | http://localhost:<port> | Direct wasmtime serve port (auto-assigned) |
| OIDC Discovery | http://localhost:3000/.well-known/openid-configuration | OIDC metadata |
| Realm Discovery | http://localhost:3000/realms/master/.well-known/openid-configuration | Per-realm metadata |
| Admin UI | http://localhost:3000 | Static SPA served from `front/admin/dist/` |

### Why `wasmtime serve`?

- Uses the **HTTP proxy** interface (`wasi:http/proxy`) — the standard for WASI P2 web servers
- No `--wasi inherit-network` needed — networking is a first-class capability
- The binary is a **WASM component** (`.wasm`), not a native executable
- Validates that all I/O is WASI-compliant (no filesystem, no threads, no process spawning)

### JAMstack Deployment Pattern

This setup mirrors production deployment:

```
Production CDN (static files)          Edge Runtime (WASM)
         ↓                                        ↓
    index.html                            wasmtime serve
    dist/app.js                                 ↓
    dist/styles.css                       PostgreSQL
         ↓
    AJAX calls → /api/*, /oidc/*, /realms/*
```

The proxy in `oidc-wasm-dev` acts like a CDN edge node: static files are served directly, API calls are forwarded to the WASM backend.

---

## Commands Reference

### `oidc-dev`

| Command | Description |
|---------|-------------|
| `start` | Full stack: PostgreSQL → migrations → seed data → frontend build → backend → frontend dev server → proxy |
| `db-only` | PostgreSQL container + migrations + seed data only. Keeps running until Ctrl-C. |
| `stop` | Kill all processes and remove the PostgreSQL container |
| `status` | Check which services are running on their ports |
| `logs` | Print accumulated service logs from temp directory |
| `wasm` | Start DB + build WASM + run via `wasmtime run` (legacy CLI mode) |
| `test` | Run smoke tests against a running native server |

### `oidc-wasm-dev`

| Command | Description |
|---------|-------------|
| `start` | PostgreSQL → migrations → seed data → build WASM → `wasmtime serve` |
| `stop` | Kill wasmtime and remove the PostgreSQL container |
| `status` | Show DB URL, WASM port, and process status |
| `test` | Run smoke tests against the running WASM server |

---

## Authentication

### API Key (automatic on first run)

Both dev tools automatically seed:
- `master` realm
- `admin@example.com` / `Admin123` user
- `admin-ui` OIDC client (public, PKCE required)
- Admin API key with `admin` scope

The admin API key is printed once on first startup:

```
═══════════════════════════════════════════════════════════════
  ADMIN API KEY (save this — shown only once):
  oidc_adm_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
═══════════════════════════════════════════════════════════════
```

Use this key in the `X-API-Key` header for all `/api/*` requests.

### OIDC Login

The login page at `/login` initiates the Authorization Code + PKCE flow against the `admin-ui` client.

For **password grant** (direct API login):

```bash
# Native
curl -X POST http://localhost:8080/oidc/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"Admin123"}'

# WASM
curl -X POST http://localhost:<port>/oidc/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"Admin123"}'
```

---

## Realm Theming (Phase 4)

Each realm can have a custom branded login page. Theme data is stored in the realm's `config` JSONB column under `config.theme`.

### Theme Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `login_title` | string | realm `display_name` | Title shown on the login page |
| `logo_url` | string | *(none)* | Logo image URL (optional) |
| `primary_color` | hex color | `#2563eb` | Button and accent color |
| `bg_color` | hex color | `#f8fafc` | Page background color |

### Setting a Theme via Admin API

```bash
# 1. Login to get an admin token
TOKEN=$(curl -s -X POST http://localhost:8080/oidc/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"Admin123"}' \
  | jq -r '.access_token')

# 2. Get the realm ID
REALM_ID=$(curl -s "http://localhost:8080/api/realms?limit=1" \
  -H "Authorization: Bearer $TOKEN" \
  | jq -r '.items[0].id')

# 3. Update the theme
curl -X PUT "http://localhost:8080/api/realms/$REALM_ID" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "config": {
      "theme": {
        "login_title": "Acme Corporation",
        "logo_url": "https://cdn.example.com/acme-logo.png",
        "primary_color": "#0f766e",
        "bg_color": "#f0fdfa"
      }
    }
  }'

# 4. View the branded login page
curl -s "http://localhost:8080/realms/master/login" | grep -o 'login_title\|logo_url\|primary_color\|bg_color'
```

### Setting a Theme via Admin UI

1. Open the Admin Console (`http://localhost:3000` for native, or `http://localhost:<port>` for WASM)
2. Navigate to **Realms** → Click on a realm → **Edit**
3. Scroll to the **Theme** section
4. Set:
   - **Login Title**: e.g. `Acme Corporation`
   - **Logo URL**: e.g. `https://cdn.example.com/acme-logo.png`
   - **Primary Color**: pick from color picker (e.g. `#0f766e`)
   - **Background Color**: pick from color picker (e.g. `#f0fdfa`)
5. Click **Save Changes**
6. Open `http://localhost:8080/realms/master/login` to see the branded page

### Theme in WASI Mode

Theming works identically in WASM because the HTML is generated dynamically from the database — no filesystem access is required:

```
Browser → GET /realms/master/login
              ↓
        WASM component queries PostgreSQL
              ↓
        Reads realms.config → theme JSON
              ↓
        Generates HTML in memory
              ↓
        Returns response
```

---

## WSL2 + Windows Browser Access

WSL2 runs in its own virtual network namespace. Services binding to `127.0.0.1` inside WSL2 are **not** reachable from a Windows browser. Both dev tools bind all services to `0.0.0.0` so Windows can access them via `localhost` forwarding.

If you see `ECONNREFUSED` from your Windows browser:

```bash
# In WSL — verify services are listening on 0.0.0.0
ss -tlnp | grep -E '3000|8080|3008'

# In Windows PowerShell — verify ports are forwarded
netstat -an | findstr '3000 8080 3008'
```

If ports are not forwarded, restart WSL:
```powershell
# In Windows PowerShell (admin)
wsl --shutdown
# Then restart your WSL session and run oidc-dev again
```

---

## Environment Variables

### `oidc-dev`

| Variable | Default | Description |
|----------|---------|-------------|
| `OIDC_DB_PORT` | auto | PostgreSQL port (auto-detected if unset) |
| `OIDC_SERVER_PORT` | auto | Backend server port (auto-detected if unset) |
| `OIDC_FRONTEND_PORT` | auto | Frontend dev server port (auto-detected if unset) |
| `OIDC_PROXY_PORT` | auto | Proxy port (auto-detected if unset) |
| `OIDC_DATABASE_URL` | — | Direct DB URL (skip container start) |

### `oidc-wasm-dev`

| Variable | Default | Description |
|----------|---------|-------------|
| `OIDC_SERVER_PORT` | auto | WASM server port (auto-detected if unset) |
| `OIDC_DATABASE_URL` | — | Direct DB URL (skip container start) |

---

## How It Works

### `oidc-dev`

1. **Container lifecycle** — Uses `rustainers` (Rust testcontainers library) to start a Podman PostgreSQL container. The container is automatically dropped when the process exits (Ctrl-C).
2. **Migrations** — Runs SQL files from `migrations/postgresql/` in order, tracking applied files in `_migrations` table.
3. **Seed data** — Idempotent: creates realm, user, client, and API key only if they don't exist.
4. **Frontend build** — Runs `npm install` + `node buildJs.js` in `front/admin/`.
5. **Backend** — Starts `cargo run -p openid-connect-wasi` with `OIDC_ISSUER` set to the proxy port.
6. **Proxy** — Writes a temporary Node.js proxy script that routes `/api/*`, `/oidc/*`, `/.well-known/*`, `/health` to the backend and everything else to the frontend. `http-proxy` is installed locally into a temp directory (no global npm install).

### `oidc-wasm-dev`

1. **Container lifecycle** — Same as `oidc-dev`.
2. **Migrations** — Same as `oidc-dev`.
3. **Seed data** — Same as `oidc-dev`.
4. **WASM build** — Runs `cargo build -p openid-connect-wasi --target wasm32-wasip2 --release`.
5. **Serve** — Starts `wasmtime serve` with the built `.wasm` component, passing all required environment variables (`OIDC_DATABASE_URL`, `OIDC_ENCRYPTION_KEY`, etc.) via `--env` flags.

---

## Troubleshooting

### Podman not found
```bash
sudo apt-get install -y podman
```

### wasmtime not found
```bash
curl https://wasmtime.dev/install.sh -sSf | bash
```

### PostgreSQL won't start
```bash
# Check container status
podman ps -a
podman logs oidc-hub-postgres

# Reset everything
cargo run -p oidc-dev -- stop
podman rm -f oidc-hub-postgres oidc-hub-wasm-postgres
cargo run -p oidc-dev -- start
```

### Backend won't connect to DB
```bash
# Check if DB is reachable (get port from startup output)
pg_isready -h localhost -p <DB_PORT> -U postgres
```

### Port already in use
```bash
# Find and kill processes on the port
lsof -ti:3000 | xargs kill -9
lsof -ti:8080 | xargs kill -9
lsof -ti:3008 | xargs kill -9
```

### Frontend build fails
```bash
cd front/admin
npm install
node buildJs.js
```

### WASM build fails
```bash
# Ensure the wasm32-wasip2 target is installed
rustup target add wasm32-wasip2

# Try building manually
cargo build -p openid-connect-wasi --target wasm32-wasip2 --release
```

---

## Why Two Dev Tools?

| Concern | `oidc-dev` | `oidc-wasm-dev` |
|---------|------------|-----------------|
| Runtime | Native Rust binary (`cargo run`) | WASM component (`wasmtime serve`) |
| Frontend | Dev server with hot reload | Pre-built static files (JAMstack) |
| Proxy | Included (CORS elimination) | Included (static + API routing) |
| Use case | Day-to-day development | Production-like deployment testing |
| Filesystem | Full access | Zero access — validates WASI compliance |
| Threads | Full access | No threads — validates single-threaded model |
| Deployment model | Monolithic | CDN (static) + Edge Runtime (WASM) |
