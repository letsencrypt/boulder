#!/bin/bash
set -e
set -o xtrace

# Check that `minica` is installed
command -v minica >/dev/null 2>&1 || {
  echo >&2 "No 'minica' command available.";
  echo >&2 "Check your GOPATH and run: 'go get github.com/jsha/minica'.";
  exit 1;
}

# Make a server certificate (a CA will be created to issue it)
minica -domains boulder-server,boulder -ip-addresses 127.0.0.1
# Make a client certificate (reuses the CA created for the server)
minica -domains boulder-client,boulder -ip-addresses 127.0.0.1
