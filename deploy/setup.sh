#!/usr/bin/env bash
# One-command setup for a fresh Ubuntu 22.04/24.04 VPS. Run as root:
#
#   curl -fsSL https://raw.githubusercontent.com/Samkiller222/look/claude/project-thread-j1ko5n/deploy/setup.sh \
#     | bash -s -- check.example.com
#
# or, from a copy of the repo on the server:  sudo bash deploy/setup.sh check.example.com
#
# It installs Docker, a firewall and automatic security updates, starts the
# app behind Caddy (automatic HTTPS), and adds a daily database backup.
# Point the domain's DNS A record at this server before running it.
set -euo pipefail

DOMAIN="${1:-}"
REPO="${LOOK_REPO:-https://github.com/Samkiller222/look.git}"
BRANCH="${LOOK_BRANCH:-claude/project-thread-j1ko5n}"
DIR="${LOOK_DIR:-/opt/look}"

if [[ -z "$DOMAIN" ]]; then echo "usage: setup.sh <domain>" >&2; exit 1; fi
if [[ $EUID -ne 0 ]]; then echo "run as root (sudo)" >&2; exit 1; fi

echo "==> System updates and packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get upgrade -yq
apt-get install -yq docker.io docker-compose-v2 git ufw unattended-upgrades fail2ban
systemctl enable --now docker
dpkg-reconfigure -f noninteractive unattended-upgrades

echo "==> Firewall: SSH, HTTP, HTTPS only"
ufw allow OpenSSH
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 443/udp
ufw --force enable

if [[ -s /root/.ssh/authorized_keys ]]; then
  echo "==> SSH: keys only (password logins off)"
  printf 'PasswordAuthentication no\nKbdInteractiveAuthentication no\n' > /etc/ssh/sshd_config.d/90-look.conf
  systemctl reload ssh || systemctl reload sshd || true
fi

echo "==> Code in $DIR"
if [[ -f "$DIR/pyproject.toml" ]]; then
  if [[ -d "$DIR/.git" ]]; then git -C "$DIR" pull --ff-only || true; fi
elif ! git clone --depth 1 --branch "$BRANCH" "$REPO" "$DIR"; then
  echo "Could not clone $REPO. If the repo is private, copy it to $DIR first, e.g." >&2
  echo "  scp -r ./look root@<server>:$DIR   then run this script again." >&2
  exit 1
fi
cd "$DIR/deploy"

if [[ ! -f .env ]]; then
  echo "==> Settings (deploy/.env)"
  umask 077
  cat > .env <<ENV
LOOK_DOMAIN=$DOMAIN
LOOK_REGION=eu
LOOK_RETENTION_DAYS=180
LOOK_SECRET_KEY=$(openssl rand -hex 32)
ENV
fi

echo "==> Starting the app"
docker compose up -d --build

echo "==> Daily backup at 03:15, kept 14 days, in /var/backups/look"
mkdir -p /var/backups/look && chmod 700 /var/backups/look
cat > /etc/cron.d/look-backup <<CRON
15 3 * * * root cd $DIR/deploy && docker compose exec -T app python -c "import sqlite3; s=sqlite3.connect('/data/look.db'); d=sqlite3.connect('/data/backup.db'); s.backup(d); d.close()" && docker compose cp app:/data/backup.db /var/backups/look/look-\$(date +\%F).db && find /var/backups/look -name 'look-*.db' -mtime +14 -delete
CRON

echo
echo "Done. Open https://$DOMAIN (the certificate can take a minute)."
echo "Create logins with:"
echo "  cd $DIR/deploy && docker compose exec app python -m look user add --username you@example.com --role requester"
echo "  cd $DIR/deploy && docker compose exec app python -m look user add --username reviewer@example.com --role reviewer"
