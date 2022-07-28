#!/bin/bash
set -e
set -o xtrace

# Check that `minica` is installed
command -v minica >/dev/null 2>&1 || {
  echo >&2 "No 'minica' command available.";
  echo >&2 "Check your GOPATH and run: 'go get github.com/jsha/minica'.";
  exit 1;
}

for SERVICE in \
  admin-revoker \
  akamai-purger \
  bad-key-revoker \
  crl-storer \
  crl-updater \
  expiration-mailer \
  nonce \
  ocsp-responder \
  ocsp-updater \
  orphan-finder \
  wfe \
  health-checker; do
  minica -domains "${SERVICE}.boulder"
done

for SERVICE in publisher ra ca sa va ; do
  minica -domains "${SERVICE}.boulder,${SERVICE}1.boulder,${SERVICE}2.boulder"
done
