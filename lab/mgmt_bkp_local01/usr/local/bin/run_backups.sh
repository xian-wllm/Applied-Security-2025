#!/bin/bash

set -euo pipefail

LOGTAG="backup-run"
NOW="$(date -u +%Y%m%dT%H%M%SZ)"

BASE_REPO_DIR="/backup/repos"
STAGING="/backup/tmp"

# Vault
VAULT_ADDR="${VAULT_ADDR:-https://10.50.40.2:8200}"
ROLE_ID_FILE="/run/secrets/vault_backup_role_id"
SECRET_ID_FILE="/run/secrets/vault_backup_secret_id"

# Borg
BORG_PASSPHRASE_FILE="/run/secrets/borg_passphrase"

log() { logger -t "$LOGTAG" "$*"; echo "[$LOGTAG] $*"; }

require_file() {
  local f="$1"
  if [ ! -r "$f" ]; then
    log "ERROR: required file '$f' not readable"
    exit 1
  fi
}

init_repo() {
  local name="$1"
  local repo="${BASE_REPO_DIR}/${name}"
  if [ ! -d "$repo" ] || [ ! -f "$repo/config" ]; then
    log "initialising Borg repo ${repo}"
    mkdir -p "$repo"
    BORG_REPO="$repo" borg init --encryption=repokey-blake2
  fi
}

get_vault_token() {
  local role_id secret_id
  role_id="$(<"$ROLE_ID_FILE")"
  secret_id="$(<"$SECRET_ID_FILE")"

  curl -s \
    --request POST \
    --data "{\"role_id\":\"${role_id}\",\"secret_id\":\"${secret_id}\"}" \
    "${VAULT_ADDR}/v1/auth/approle/login" \
    | jq -r '.auth.client_token'
}

get_db_creds() {
  local role="$1"   # e.g. mysql-db01-backup
  curl -s \
    -H "X-Vault-Token: ${VAULT_TOKEN}" \
    "${VAULT_ADDR}/v1/database/creds/${role}"
}

mk_mysql_defaults_file() {
  local user="$1"
  local pass="$2"
  local host="$3"
  local port="$4"
  local file="$5"

  cat >"$file" <<EOF
[client]
user=${user}
password=${pass}
host=${host}
port=${port}
EOF
  chmod 600 "$file"
}

main() {
  log "=== backup run starting at $NOW ==="

  require_file "$ROLE_ID_FILE"
  require_file "$SECRET_ID_FILE"
  require_file "$BORG_PASSPHRASE_FILE"

  mkdir -p "$STAGING"
  chmod 700 "$STAGING"

  export BORG_PASSPHRASE
  BORG_PASSPHRASE="$(<"$BORG_PASSPHRASE_FILE")"

  # ---------- 1) Vault Raft snapshot via AppRole ----------
  log "Vault: obtaining short-lived token via AppRole"
  VAULT_TOKEN="$(get_vault_token)"

  VAULT_SNAP="${STAGING}/vault-raft-${NOW}.snap"
  log "Vault: requesting Raft snapshot from ${VAULT_ADDR}"

  curl -s \
    -H "X-Vault-Token: ${VAULT_TOKEN}" \
    -o "${VAULT_SNAP}" \
    "${VAULT_ADDR}/v1/sys/storage/raft/snapshot"

  if [ ! -s "$VAULT_SNAP" ]; then
    log "ERROR: Vault snapshot file ${VAULT_SNAP} is empty"
    exit 1
  fi

  init_repo vault
  log "Vault: storing snapshot in Borg"
  BORG_REPO="${BASE_REPO_DIR}/vault" borg create --stats "::vault-${NOW}" "${VAULT_SNAP}"

  # ---------- 2) MySQL via Vault dynamic creds ----------
  log "MySQL: obtaining dynamic backup creds from Vault"

  # db01
  DB01_JSON="$(get_db_creds mysql-db01-backup)"
  DB01_USER="$(echo "$DB01_JSON" | jq -r .data.username)"
  DB01_PASS="$(echo "$DB01_JSON" | jq -r .data.password)"

  DB01_DEF="${STAGING}/mysql-db01.cnf"

  mk_mysql_defaults_file "$DB01_USER" "$DB01_PASS" "10.50.30.2" "3306" "$DB01_DEF"

  MYSQL1_DUMP="${STAGING}/mysql-data_db01-${NOW}.sql.gz"

  log "MySQL: dumping data_db01 to ${MYSQL1_DUMP}"
  mysqldump \
    --defaults-extra-file="$DB01_DEF" \
    --all-databases \
    --single-transaction \
    --routines \
    --events \
    --hex-blob \
    | gzip > "$MYSQL1_DUMP"

  init_repo mysql
  log "MySQL: storing dumps in Borg"
  BORG_REPO="${BASE_REPO_DIR}/mysql" borg create --stats \
    "::mysql-${NOW}" \
    "${MYSQL1_DUMP}"

  # delete temp defaults so passwords don't linger on disk
  shred -u "$DB01_DEF" 2>/dev/null || rm -f "$DB01_DEF"

  # ---------- 4) Prune ----------
  log "Pruning Borg repos (Vault/MySQL)"

  BORG_REPO="${BASE_REPO_DIR}/vault"  borg prune --list --keep-daily=7 --keep-weekly=4 --keep-monthly=6
  BORG_REPO="${BASE_REPO_DIR}/mysql"  borg prune --list --keep-daily=7 --keep-weekly=4 --keep-monthly=6

  # ---------- 5) Cleanup staging ----------
  find "$STAGING" -type f -mtime +2 -delete || true

  log "=== backup run completed at $NOW ==="
}

main "$@"
