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
COMMIT_TIMESTAMP="$(git show -s --format=%ct HEAD)"
COMMIT_DATE_ISO8601="$(TZ=UTC0 git show -s --format=%cd --date=format:%Y-%m-%dT%H:%M:%SZ HEAD)"
VERSION="${GO_VERSION}.${COMMIT_TIMESTAMP}"

docker buildx build \
    --file Containerfile \
    --build-arg "COMMIT_ID=${COMMIT_ID}" \
    --build-arg "COMMIT_TIMESTAMP=${COMMIT_TIMESTAMP}" \
    --build-arg "COMMIT_DATE_ISO8601=${COMMIT_DATE_ISO8601}" \
    --build-arg "GO_VERSION=${GO_VERSION}" \
    --build-arg "VERSION=${VERSION}" \
    --tag "boulder:${VERSION}" \
    --tag "boulder:${COMMIT_ID}" \
    --tag boulder \
    .

docker run boulder tar -C /opt/boulder --mtime="@${COMMIT_TIMESTAMP}" --owner=0 --group=0 --numeric-owner --sort=name -cp . | gzip -n > "./boulder-${VERSION}-${COMMIT_ID}.${ARCH}.tar.gz"
# Produces e.g. boulder-1.25.0.1754519595-591c0545.x86_64.deb
docker run -v .:/boulderrepo \
  -e "COMMIT_ID=${COMMIT_ID}" \
  -e "VERSION=${VERSION}" \
  -e "SOURCE_DATE_EPOCH=${COMMIT_TIMESTAMP}" \
  boulder \
  /boulderrepo/tools/make-deb.sh
