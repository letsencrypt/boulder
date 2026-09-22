#!/bin/sh
set -eu

until [ -f /boulder/test/certs/sunlight/seed.bin ] &&
      [ -f /boulder/test/certs/sunlight/mtc-logs.txt ]; do
  echo "waiting for generated keys and log list"
  sleep 1
done

if [ ! -f /sunlight-data/checkpoints.db ]; then
  sqlite3 /sunlight-data/checkpoints.db \
    "CREATE TABLE checkpoints (logID BLOB PRIMARY KEY, body BLOB NOT NULL) STRICT"
fi

# "The inception date is the only date on which Sunlight will create the log if
# it doesn't exist yet", so stamp the current date for the first boot.
sed "s/@INCEPTION@/$(date +%Y-%m-%d)/" /boulder/test/sunlight/sunlight.yaml \
  > /tmp/sunlight.yaml

exec sunlight -c /tmp/sunlight.yaml
