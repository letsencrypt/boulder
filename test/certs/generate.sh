#!/bin/bash
set -e

cd "$(realpath -- $(dirname -- "$0"))/../.."

# Check that `minica` is installed
command -v minica >/dev/null 2>&1 || {
  echo >&2 "No 'minica' command available.";
  echo >&2 "Check your GOPATH and run: 'go install github.com/jsha/minica@latest'.";
  exit 1;
}

ipki() (
  # Minica generates everything in-place, so we need to cd into the subdirectory.
  # This function executes in a subshell, so this cd does not affect the parent
  # script.
  mkdir -p test/certs/ipki
  pushd test/certs/ipki

  # Create a generic cert which can be used by our test-only services that
  # aren't sophisticated enough to present a different name. This first
  # invocation also creates the issuer key, so the loops below can run in the
  # background without racing to create it.
  minica -domains localhost --ip-addresses 127.0.0.1

  # Used by challtestsrv to negotiate DoH handshakes. Even though we think of
  # challtestsrv as being external to our infrastructure (because it hosts the
  # DNS records that the tests validate), it *also* takes the place of our
  # recursive resolvers, so the DoH certificate that it presents to the VAs is
  # part of our internal PKI.
  minica -ip-addresses 10.77.77.77,10.88.88.88

  # Presented by the WFE's TLS server, when configured. Normally the WFE lives
  # behind another TLS-terminating server like nginx or apache, so the cert that
  # it presents to that layer is also part of the internal PKI.
  minica -domains "boulder"

  # Presented by the test redis cluster. Contains IP addresses because Boulder
  # components find individual redis servers via SRV records.
  minica -domains redis -ip-addresses 10.77.77.4,10.77.77.5

  # Used by Boulder gRPC services as both server and client mTLS certificates.
  for SERVICE in admin consul wfe bad-key-revoker \
    crl-updater crl-storer health-checker sfe email-exporter mtca mtcb; do
    minica -domains "${SERVICE}.boulder" &
  done

  # Same as above, for services that we run multiple copies of.
  for SERVICE in publisher nonce ra ca sa va rva ; do
    minica -domains "${SERVICE}.boulder,${SERVICE}1.boulder,${SERVICE}2.boulder" &
  done

  wait

  # minica sets restrictive directory permissions, but we don't want that
  chmod -R go+rX .

  popd
)

webpki() (
  # The webpki keys live in SoftHSM tokens, and webpki.go always creates new
  # ones. Empty the directory rather than removing it, because it's a bind
  # mount source.
  rm -rf test/certs/.softhsm-tokens/*
  # Because it invokes the ceremony tool, webpki.go expects to be invoked with
  # the root of the boulder repo as the current working directory.
  GOBIN=$PWD/bin/ go install ./cmd/ceremony
  mkdir -p ./test/certs/webpki
  go run ./test/certs/webpki.go
)

sunlight() (
  mkdir -p test/certs/sunlight
  go run ./test/sunlight/genkeys/main.go -output-dir test/certs/sunlight -mtca-public-key test/certs/webpki/mtca-1.pubkey.pem
)

REGENERATED=false

# generate deletes the directory $1 and regenerates it with the function $2 if
# the directory is missing, was only partly generated, or is older than any of
# the remaining arguments, which are the scripts and configs it's made from.
generate() {
  local dir="$1" fn="$2"
  shift 2
  local stamp="${dir}/.generated"
  if [ -f "${stamp}" ] && [ -z "$(find "$@" -newer "${stamp}" -print -quit)" ]; then
    return
  fi
  echo "Generating ${dir#test/certs/}/..."
  rm -rf "${dir}"
  "${fn}"
  # Written last, so an interrupted run is redone.
  touch "${stamp}"
  REGENERATED=true
}

generate test/certs/ipki ipki test/certs/generate.sh
generate test/certs/webpki webpki test/certs/generate.sh test/certs/webpki.go test/certs/*.yaml
generate test/certs/sunlight sunlight test/certs/generate.sh test/sunlight/genkeys test/certs/webpki/mtca-1.pubkey.pem

if [ "${REGENERATED}" = true ]; then
  echo "Containers left running by an earlier run still use the old files." \
    "If there are any, reset them with 'docker compose down --volumes --remove-orphans'."
fi
