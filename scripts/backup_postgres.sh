#!/usr/bin/env bash
set -euo pipefail
STAMP=$(date -u +"%Y%m%dT%H%M%SZ")
BACKUP_DIR="/var/backups/mcas"
mkdir -p "$BACKUP_DIR"
FILE="$BACKUP_DIR/mcas_${STAMP}.sql.gz"
docker exec mcas-postgres-1 pg_dump -U "${POSTGRES_USER:-mcas}" "${POSTGRES_DB:-mcas}" | gzip > "$FILE"
find "$BACKUP_DIR" -type f -name "*.sql.gz" -mtime +14 -delete
echo "Backup saved: $FILE"
