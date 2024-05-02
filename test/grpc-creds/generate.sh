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

SERVICE_WITH_SINGLE_SAN=(
  "admin-revoker"
  "expiration-mailer"
  "ocsp-responder"
  "consul"
  "wfe"
  "akamai-purger"
  "bad-key-revoker"
  "crl-updater"
  "crl-storer"
  "health-checker"
)
for SERVICE in ${SERVICE_WITH_SINGLE_SAN[@]}; do
  minica -domains "${SERVICE}.boulder"
done

SERVICE_WITH_MULTIPLE_SANS=(
  "publisher"
  "nonce"
  "ra"
  "ca"
  "sa"
  "va"
  "rva"
)
for SERVICE in ${SERVICE_WITH_MULTIPLE_SANS[@]}; do
  minica -domains "${SERVICE}.boulder,${SERVICE}1.boulder,${SERVICE}2.boulder"
done

minica -ip-addresses 10.77.77.77,10.88.88.88

# These files are used by the TestTLSConfigLoad unit test
minica -ca-cert externalCA.pem -ca-key externalCA-key.pem -domains applicationloadbalancer.example.com
cat externalCA.pem externalCA.pem > duplicate-roots.pem
cat minica.pem externalCA.pem > multiple-roots.pem
# grpc/creds/creds.go:
minica -domains "creds-test" -ip-addresses "127.0.0.1"

# minica sets restrictive directory permissions, but we don't want that
chmod -R go+rX .
