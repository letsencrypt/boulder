#!/bin/bash
set -e
set -o xtrace

cd "$(realpath -- $(dirname -- "$0"))"

# Check that `minica` is installed
command -v minica >/dev/null 2>&1 || {
  echo >&2 "No 'minica' command available.";
  echo >&2 "Check your GOPATH and run: 'go get github.com/jsha/minica'.";
  exit 1;
}

minica -domains boulder
minica -domains boulder-redis
minica -domains redis -ip-addresses 10.33.33.2,10.33.33.3,10.33.33.4,10.33.33.5,10.33.33.6,10.33.33.7,10.33.33.8,10.33.33.9

# minica sets restrictive directory permissions, but we don't want that
chmod -R go+rX .
