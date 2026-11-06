#!/bin/sh
set -eu

# The sunlight config file, whose checkpoints path names this mirror's lock
# database. The two dev mirrors share the data volume.
CONFIG="${1:-/boulder/test/sunlight/sunlight.yaml}"
CHECKPOINTS="$(sed -n 's/^checkpoints: //p' "$CONFIG")"

until [ -f /boulder/test/certs/sunlight/seed.bin ] &&
      [ -f /boulder/test/certs/sunlight/mtc-logs.txt ]; do
  echo "waiting for generated keys and log list"
  sleep 1
done

if [ ! -f "$CHECKPOINTS" ]; then
  sqlite3 "$CHECKPOINTS" \
    "CREATE TABLE checkpoints (logID BLOB PRIMARY KEY, body BLOB NOT NULL) STRICT"
fi

exec sunlight -c "$CONFIG"
