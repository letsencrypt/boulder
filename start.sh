#!/bin/bash
# Run both boulder and cfssl, using test configs.
if type realpath >/dev/null 2>/dev/null; then
  cd $(realpath $(dirname $0))
fi

# Kill all children on exit.
export BOULDER_CONFIG=${BOULDER_CONFIG:-test/boulder-config.json}

exec go run ./cmd/boulder/main.go
