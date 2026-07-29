#!/bin/bash
set -feuo pipefail

# If a command was passed, run that instead of the minio server.
if [[ $# -ne 0 ]]; then
    exec "$@"
fi

# Otherwise, start and init minio.
minio server /data &
MINIO_PID="$!"

# Idempotently create the tile storage bucket, then exit. `mc` is the MinIO
# command-line client; it addresses servers by registered aliases not URLs,
# so we must register the server as an alias before running `mc mb` (make
# bucket).
#
# `mc alias set` probes the server and exits nonzero if it's unreachable, so
# our retry loop also doubles as a readiness check. For more information see:
#
# - https://docs.min.io/aistor/reference/cli/mc-mb/#alias
# - https://docs.min.io/aistor/reference/cli/mc-alias/mc-alias-set/
until mc alias set local http://localhost:9000 "$MINIO_ROOT_USER" "$MINIO_ROOT_PASSWORD" ; do
  sleep 1
done;
mc mb -q --ignore-existing local/boulder-mtc-tiles
# Allow HTTP fetches of the tiles.
mc anonymous -q set download local/boulder-mtc-tiles

# Put a simple file at the root of the bucket. This is useful for health checking.
# Once this file exists, the bucket is fully initialized.
echo "Boulder's MTCA keeps its tiles here" > /tmp/index.html
mc cp -q /tmp/index.html local/boulder-mtc-tiles

wait "$MINIO_PID"
