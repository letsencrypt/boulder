#!/bin/bash
# Run both boulder and cfssl, using test configs.
if type realpath >/dev/null 2>/dev/null; then
  cd $(realpath $(dirname $0))
fi

# Kill all children on exit.
trap "trap - SIGTERM && kill -- -$$" SIGINT SIGTERM EXIT

BOULDER_CONFIG=${BOULDER_CONFIG:-test/boulder-config.json}

go run ./cmd/boulder/main.go &
go run Godeps/_workspace/src/github.com/cloudflare/cfssl/cmd/cfssl/cfssl.go \
  -loglevel 0 \
  serve \
  -port 9000 \
  -ca test/test-ca.pem \
  -ca-key test/test-ca.key \
  -config test/cfssl-config.json &

sleep 100000
