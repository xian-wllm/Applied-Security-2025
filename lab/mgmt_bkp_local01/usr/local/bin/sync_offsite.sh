#!/bin/bash
set -euo pipefail

LOGTAG="backup-sync"
BASE_REPO_DIR="/backup/repos"
OFFSITE_TARGET="backup@10.60.60.2:/backup/repos"

log() { logger -t "$LOGTAG" "$*"; echo "[$LOGTAG] $*"; }

log "starting offsite sync: ${BASE_REPO_DIR} -> ${OFFSITE_TARGET}"

rsync -a --delete \
  -e "ssh -i /home/backup/.ssh/id_ed25519 -o StrictHostKeyChecking=no" \
  "${BASE_REPO_DIR}/" \
  "${OFFSITE_TARGET}/"

log "offsite sync completed"
