#!/usr/bin/env bash
# One-command Debian 13 deployment for xsukax CipherVault.
set -Eeuo pipefail
cd "$(dirname "$(readlink -f "$0")")"
PROJECT_DIR="$(pwd)"

if [[ "$EUID" -ne 0 ]]; then
  exec sudo bash "$0" "$@"
fi
if [[ ! -r /etc/os-release ]]; then echo "Unsupported host: /etc/os-release missing" >&2; exit 1; fi
source /etc/os-release
if [[ "${ID:-}" != "debian" || "${VERSION_ID:-}" != "13" ]]; then
  echo "This installer targets Debian 13 (found ${PRETTY_NAME:-unknown})." >&2
  exit 1
fi
PORT="${VAULT_PORT:-8743}"
if [[ ! "$PORT" =~ ^[0-9]{2,5}$ ]] || (( 10#$PORT < 1024 || 10#$PORT > 65535 )); then
  echo "VAULT_PORT must be in the range 1024-65535" >&2; exit 1
fi

install_docker() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y ca-certificates curl python3 gnupg
  install -m 0755 -d /etc/apt/keyrings
  if [[ ! -s /etc/apt/keyrings/docker.asc ]]; then
    curl -fsSL --retry 3 https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
  fi
  chmod a+r /etc/apt/keyrings/docker.asc
  local arch
  arch="$(dpkg --print-architecture)"
  printf 'Types: deb\nURIs: https://download.docker.com/linux/debian\nSuites: %s\nComponents: stable\nArchitectures: %s\nSigned-By: /etc/apt/keyrings/docker.asc\n' \
    "${VERSION_CODENAME:-trixie}" "$arch" > /etc/apt/sources.list.d/docker.sources
  apt-get update
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  systemctl enable --now docker
}

if ! command -v docker >/dev/null 2>&1 || ! docker compose version >/dev/null 2>&1; then
  echo '[1/5] Installing official Docker Engine and Compose plugin...'
  install_docker
else
  echo '[1/5] Docker and Compose already installed.'
  if command -v systemctl >/dev/null 2>&1; then systemctl start docker || true; fi
fi
if ! docker info >/dev/null 2>&1; then echo 'Docker daemon unavailable.' >&2; exit 1; fi

echo '[2/5] Preparing private storage and one-time setup token...'
install -d -m 0700 "$PROJECT_DIR/appdata" "$PROJECT_DIR/appdata/blobs"
chmod 0700 "$PROJECT_DIR/appdata" "$PROJECT_DIR/appdata/blobs"
# If the database contains an administrator, never mint a new bootstrap token.
INITIALIZED="$(python3 - "$PROJECT_DIR/appdata/vault.sqlite3" <<'PY'
import sqlite3,sys,os
if not os.path.exists(sys.argv[1]): print('no')
else:
    try:
        with sqlite3.connect(sys.argv[1]) as db:
            print('yes' if db.execute('SELECT count(*) FROM users').fetchone()[0] else 'no')
    except sqlite3.Error:
        print('unknown')
PY
)"
if [[ "$INITIALIZED" == "no" && ! -f "$PROJECT_DIR/appdata/bootstrap.token" ]]; then
  python3 - "$PROJECT_DIR/appdata/bootstrap.token" <<'PY'
import os, secrets, sys
fd=os.open(sys.argv[1], os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
with os.fdopen(fd,'w',encoding='ascii') as f:
    f.write(secrets.token_urlsafe(40)+'\n')
PY
fi
if [[ "$INITIALIZED" == "yes" ]]; then
  rm -f "$PROJECT_DIR/appdata/bootstrap.token"
fi
chown -R 10001:10001 "$PROJECT_DIR/appdata"
find "$PROJECT_DIR/appdata" -type f -name 'bootstrap.token' -exec chmod 0600 {} +

if [[ ! -e .env ]]; then
  echo '[3/5] Generating default environment settings...'
  cat > .env <<EOF
VAULT_DATA_DIR=/data
VAULT_PORT=$PORT
COOKIE_SECURE=1
TRUST_CF_HEADERS=1
MAX_FILE_BYTES=5368709120
EOF
  chmod 0600 .env
else
  echo '[3/5] Reusing your existing .env file.'
fi

echo '[4/5] Building and starting Docker container...'
docker compose up -d --build

echo '[5/5] Deployment status:'
docker compose ps
printf '\n%s\n' '=============================================='
printf '%s\n' 'xsukax CipherVault is deployed.'
printf 'Local HTTP origin for cloudflared: http://127.0.0.1:%s\n' "$PORT"
printf '%s\n' 'Visit your Cloudflare HTTPS hostname to initialize the administrator.'
if [[ "$INITIALIZED" == "no" && -f "$PROJECT_DIR/appdata/bootstrap.token" ]]; then
  printf '\n%s\n' 'INITIAL SETUP CODE (one-time; keep secret):'
  cat "$PROJECT_DIR/appdata/bootstrap.token"
else
  printf '%s\n' 'Administrator setup is already completed; sign in with your existing password.'
fi
printf '\n%s\n' 'Only a loopback port is published. Do not expose this HTTP origin publicly.'
printf '%s\n' '=============================================='
