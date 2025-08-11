#!/usr/bin/env bash
#
# Build a Docker container of Boulder (plus ancillary files), and emit both
# a .tar.gz and a .deb in the current directory, containing Boulder plus the
# ancillary files.
#

set -ex

# Without this, `go install` produces:
# # runtime/cgo
# gcc: error: unrecognized command-line option '-m64'
if [ "$(uname -m)" = "arm64" ]; then
  export DOCKER_DEFAULT_PLATFORM=linux/amd64
fi

if [ -z "${GO_VERSION}" ] ; then
  echo "GO_VERSION not set"
  exit 1
fi

ARCH="$(uname -m)"
COMMIT_ID="$(git rev-parse --short=8 HEAD)"
VERSION="${GO_VERSION}.$(date +%s)"

docker buildx build \
    --build-arg "COMMIT_ID=${COMMIT_ID}" \
    --build-arg "GO_VERSION=${GO_VERSION}" \
    --build-arg "VERSION=${VERSION}" \
    --tag "boulder:${VERSION}" \
    --tag "boulder:${COMMIT_ID}" \
    --tag boulder \
    .

docker run boulder tar -C /opt/boulder -cpz . > "./boulder-${VERSION}-${COMMIT_ID}.${ARCH}.tar.gz" .
# Produces e.g. boulder-1.24.5.1754519595-591c0545.x86_64.deb
docker run -v .:/boulderrepo \
  -e "COMMIT_ID=$(git rev-parse --short=8 HEAD)" \
  -e "VERSION=${VERSION}" \
  boulder \
  /boulderrepo/tools/make-deb.sh
