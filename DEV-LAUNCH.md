# Dev Environment — `oidc-dev`

The `oidc-dev` Rust crate is the single-command development orchestrator for the OpenID Connect WASI Hub. It replaces the legacy `dev-launch.sh` bash script with a cross-platform, typed, and container-aware implementation.

## Prerequisites (WSL)

```bash
# Podman (for PostgreSQL container)
sudo apt-get update && sudo apt-get install -y podman

# Node.js (for frontend build + proxy)
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
sudo apt-get install -y nodejs

# Rust (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

## Quick Start

```bash
# Navigate to project directory in WSL
cd /mnt/d/dev/openid_connect_wasi

# Start everything (DB + migrations + seed data + backend + frontend + proxy)
cargo run -p oidc-dev -- start

# Check status
cargo run -p oidc-dev -- status

# Start only the database (for running tests manually)
cargo run -p oidc-dev -- db-only

# Stop everything (kills processes + removes container)
cargo run -p oidc-dev -- stop
```

## Commands

| Command | Description |
|---------|-------------|
| `start` | Full stack: PostgreSQL container → migrations → seed data → frontend build → backend → frontend dev server → proxy |
| `db-only` | PostgreSQL container + migrations + seed data only. Keeps running until Ctrl-C. |
| `stop` | Kill all processes and remove the PostgreSQL container |
| `status` | Check which services are running on their ports |
| `logs` | Print accumulated service logs from temp directory |

## Architecture

```
Browser → Proxy (port 3000) → Backend (port 8080)  /api/*, /oidc/*, /.well-known/*, /health
                      ↘ Frontend (port 3008)  /* (SPA fallback)
```

The proxy eliminates CORS issues by serving both frontend and backend from the same origin.

## WSL2 + Windows Browser Access

WSL2 runs in its own virtual network namespace. Services binding to `127.0.0.1` inside WSL2 are **not** reachable from a Windows browser. `oidc-dev` binds all services to `0.0.0.0` so Windows can access them via `localhost` forwarding.

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

## URLs

| Service | URL | Description |
|---------|-----|-------------|
| **Proxy (use this)** | http://localhost:3000 | Single entrypoint — open in browser |
| Backend API | http://localhost:8080 | Direct backend access |
| Frontend dev | http://localhost:3008 | Direct frontend access |
| OIDC Discovery | http://localhost:3000/.well-known/openid-configuration | OIDC metadata |

## Authentication

### API Key (automatic on first run)

`oidc-dev start` automatically seeds:
- `master` realm
- `admin@localhost` / `admin` user
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

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `OIDC_DB_PORT` | auto | PostgreSQL port (auto-detected if unset) |
| `OIDC_SERVER_PORT` | auto | Backend server port (auto-detected if unset) |
| `OIDC_FRONTEND_PORT` | auto | Frontend dev server port (auto-detected if unset) |
| `OIDC_PROXY_PORT` | auto | Proxy port (auto-detected if unset) |
| `OIDC_DATABASE_URL` | — | Direct DB URL (skip container start) |

## How It Works

1. **Container lifecycle** — Uses `rustainers` (Rust testcontainers library) to start a Podman PostgreSQL container. The container is automatically dropped when the process exits (Ctrl-C).
2. **Migrations** — Runs SQL files from `migrations/postgresql/` in order, tracking applied files in `_migrations` table.
3. **Seed data** — Idempotent: creates realm, user, client, and API key only if they don't exist.
4. **Frontend build** — Runs `npm install` + `node buildJs.js` in `front/admin/`.
5. **Backend** — Starts `cargo run -p openid-connect-wasi` with `OIDC_ISSUER` set to the proxy port.
6. **Proxy** — Writes a temporary Node.js proxy script that routes `/api/*`, `/oidc/*`, `/.well-known/*`, `/health` to the backend and everything else to the frontend. `http-proxy` is installed locally into a temp directory (no global npm install).

## Troubleshooting

### Podman not found
```bash
sudo apt-get install -y podman
```

### PostgreSQL won't start
```bash
# Check container status
podman ps -a
podman logs oidc-hub-postgres

# Reset everything
cargo run -p oidc-dev -- stop
podman rm -f oidc-hub-postgres
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

## Why `oidc-dev` instead of `dev-launch.sh`?

| Concern | `dev-launch.sh` (legacy) | `oidc-dev` (current) |
|---------|--------------------------|----------------------|
| Portability | Bash-only, WSL required | Rust — compiles anywhere |
| Type safety | None | Full Rust type checking |
| Container tracking | PID files, manual cleanup | `rustainers` — auto-drop on exit |
| Error handling | `set -e` | Structured `Result` + `anyhow` |
| Process management | `nohup` + PID files | `tokio::process::Child` + `kill().await` |
| Proxy module | Global `npm install -g http-proxy` | Local temp install via `NODE_PATH` |
| Seed data | External `psql` + example binary | Built-in, idempotent |
