#!/usr/bin/env bash

set -feuo pipefail

ARGS="-p 4218 \
    --tls \
    --cert /test/certs/ipki/redis/cert.pem \
    --key /test/certs/ipki/redis/key.pem \
    --cacert /test/certs/ipki/minica.pem \
    --user boulder \
    --pass 824968fa490f4ecec1e52d5e34916bdb60d45f8d"

exec docker compose exec bredis_1 redis-cli $ARGS "${@}"
