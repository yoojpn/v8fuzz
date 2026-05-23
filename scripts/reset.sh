#!/usr/bin/env bash
set -e

WORKER_URL="${WORKER_URL:-https://v8fuzz.yoyosan0929.workers.dev}"
API_SECRET="${API_SECRET:-}"
DB_PATH="${DB_PATH:-/opt/v8fuzz/db/fuzz.db}"
LOG_DIR="${LOG_DIR:-/opt/v8fuzz/logs}"
CORPUS_DIR="${CORPUS_DIR:-/opt/v8fuzz/corpus}"
TMPFS_DIR="${TMPFS_DIR:-/tmp/fuzz}"

if [ -z "$API_SECRET" ]; then
  echo "Usage: API_SECRET=xxx [WORKER_URL=...] bash reset.sh"
  exit 1
fi

echo "=== 1. Cloudflare KV reset ==="
curl -sf -X POST "$WORKER_URL/admin/reset" \
  -H "X-API-Secret: $API_SECRET" \
  && echo " OK" || echo " FAILED"

echo "=== 2. SQLite DB reset ==="
if [ -f "$DB_PATH" ]; then
  rm -f "$DB_PATH"
  echo " Deleted: $DB_PATH"
else
  echo " Not found (skip): $DB_PATH"
fi

echo "=== 3. Log files reset ==="
if [ -d "$LOG_DIR" ]; then
  rm -rf "$LOG_DIR"/*
  echo " Cleared: $LOG_DIR"
else
  echo " Not found (skip): $LOG_DIR"
fi

echo "=== 4. Corpus reset ==="
if [ -d "$CORPUS_DIR" ]; then
  find "$CORPUS_DIR" -mindepth 1 -not -name "*.py" -delete
  echo " Cleared: $CORPUS_DIR"
else
  echo " Not found (skip): $CORPUS_DIR"
fi

echo "=== 5. tmpfs reset ==="
if [ -d "$TMPFS_DIR" ]; then
  rm -rf "$TMPFS_DIR"/*
  echo " Cleared: $TMPFS_DIR"
else
  echo " Not found (skip): $TMPFS_DIR"
fi

echo ""
echo "Done. 'python3 controller/main.py' で再起動してください。"
