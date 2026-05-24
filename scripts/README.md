# OIDC Hub Scripts

Operational scripts for backup, deployment, rollback, and coverage.

## Quick Reference

| Script | Purpose | Usage |
|--------|---------|-------|
| `backup-db.sh` | PostgreSQL database backup | `./scripts/backup-db.sh --db-url $OIDC_DATABASE_URL` |
| `deploy.sh` | Build + deploy + verify | `./scripts/deploy.sh` |
| `rollback.sh` | Restore previous WASM version | `./scripts/rollback.sh --list` |
| `check-coverage.sh` | Measure code coverage | `./scripts/check-coverage.sh` |
| `package-release.sh` | Build a release bundle with both WASM artifacts and the minified frontend | `./scripts/package-release.sh --version v0.1.0` |

---

## backup-db.sh

Creates a compressed PostgreSQL dump with timestamp and automatic rotation.

```bash
# Basic usage (uses $OIDC_DATABASE_URL)
./scripts/backup-db.sh

# Custom output directory
./scripts/backup-db.sh --output /var/backups/oidc

# Keep last 30 backups
./scripts/backup-db.sh --retain 30
```

### Cron Setup (daily at 2 AM)

```crontab
0 2 * * * /path/to/oidc-hub/scripts/backup-db.sh --output /var/backups/oidc --retain 30 >> /var/log/oidc-backup.log 2>&1
```

### Restore from Backup

```bash
# List backup contents
pg_restore --list backups/oidc_hub_20260510_020000.dump

# Full restore (WARNING: replaces all data)
pg_restore --clean --if-exists --dbname="$OIDC_DATABASE_URL" backups/oidc_hub_20260510_020000.dump

# Selective restore (single table)
pg_restore --dbname="$OIDC_DATABASE_URL" --table=users backups/oidc_hub_20260510_020000.dump
```

---

## deploy.sh

Full deployment pipeline: build → backup → migrate → deploy → verify.

```bash
# Full deploy (build + migrate + health check)
./scripts/deploy.sh

# Deploy pre-built artifact
./scripts/deploy.sh --wasm-path ./target/wasm32-wasip2/release/openid_connect_wasi.wasm

# Deploy without build or migrations
./scripts/deploy.sh --skip-build --skip-migrate

# Deploy to custom directory
./scripts/deploy.sh --wasm-dir /opt/oidc-hub/wasm
```

### What It Does

1. **Build** — `cargo build -p openid-connect-wasi --target wasm32-wasip2 --release`
2. **Backup** — Copies current WASM to `wasm/versions/` with timestamp
3. **Migrate** — Runs `cargo run -p oidc-migrate -- migrate`
4. **Deploy** — Copies new WASM to active location
5. **Verify** — Health check with retries; auto-rollback hint on failure

---

## rollback.sh

Restores a previous WASM artifact version.

```bash
# List available versions
./scripts/rollback.sh --list

# Rollback to previous version
./scripts/rollback.sh

# Rollback to specific version
./scripts/rollback.sh --version 20260510_143000

# Rollback without restarting
./scripts/rollback.sh --no-restart
```

### Version Directory Structure

```
wasm/
├── openid_connect_wasi.wasm                              ← active version
└── versions/
    ├── openid_connect_wasi_20260509_120000.wasm          ← deploy backup
    ├── openid_connect_wasi_20260510_143000.wasm          ← deploy backup
    └── openid_connect_wasi_pre-rollback-20260510_150000.wasm  ← rollback backup
```

---

## package-release.sh

Creates a release bundle containing:

- `wasm/oidc_admin_wasi.wasm`
- `wasm/openid_connect_wasi.wasm`
- `front/admin/dist/` (production build with minified JS and CSS)
- deployment helper scripts
- `SHA256SUMS.txt`

```bash
# Build everything and create a versioned bundle
./scripts/package-release.sh --version v0.1.0

# Reuse already-built artifacts
./scripts/package-release.sh --skip-build
```

### Output

```text
dist/packages/
├── openid-connect-wasi-v0.1.0/
└── openid-connect-wasi-v0.1.0.tar.gz
```

---

## check-coverage.sh

Measures code coverage using `cargo llvm-cov`.

```bash
# Run coverage with summary
./scripts/check-coverage.sh

# Generate HTML report
./scripts/check-coverage.sh --html
# Opens: target/llvm-cov/html/index.html
```

### Requirements

- Rust nightly or stable with `llvm-tools-preview` component
- `cargo-llvm-cov` (auto-installed if missing)

---

## Environment Variables

| Variable | Used By | Description |
|----------|---------|-------------|
| `OIDC_DATABASE_URL` | backup-db, deploy | PostgreSQL connection URL |
| `OIDC_BACKUP_DIR` | backup-db | Override backup output directory |
