#!/bin/bash
set -e

cd "$(realpath -- $(dirname -- "$0"))"

ipki() (
  # Check that `minica` is installed
  command -v minica >/dev/null 2>&1 || {
    echo >&2 "No 'minica' command available.";
    echo >&2 "Check your GOPATH and run: 'go install github.com/jsha/minica@latest'.";
    exit 1;
  }

  # Minica generates everything in-place, so we need to cd into the subdirectory.
  # This function executes in a subshell, so this cd does not affect the parent
  # script.
  mkdir ipki
  cd ipki

  # Used by challtestsrv to negotiate DoH handshakes.
  # TODO: Move this out of the ipki directory.
  # This also creates the issuer key, so the loops below can run in the
  # background without competing over who gets to create it.
  minica -ip-addresses 10.77.77.77,10.88.88.88

  for SERVICE in admin-revoker expiration-mailer ocsp-responder consul \
    wfe akamai-purger bad-key-revoker crl-updater crl-storer \
    health-checker; do
    minica -domains "${SERVICE}.boulder" &
  done

  for SERVICE in publisher nonce ra ca sa va rva ; do
    minica -domains "${SERVICE}.boulder,${SERVICE}1.boulder,${SERVICE}2.boulder" &
  done

  wait

  # minica sets restrictive directory permissions, but we don't want that
  chmod -R go+rX .
)

webpki() (
  # Because it invokes the ceremony tool, webpki.go expects to be invoked with
  # the root of the boulder repo as the current working directory.
  # This function executes in a subshell, so this cd does not affect the parent
  # script.
  cd ../..
  mkdir ./test/certs/webpki
  go run ./test/certs/webpki.go
)

if ! [ -d ipki ]; then
  echo "Generating ipki/..."
  ipki
fi

if ! [ -d webpki ]; then
  echo "Generating webpki/..."
  webpki
fi
