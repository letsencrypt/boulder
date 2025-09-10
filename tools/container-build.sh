#!/usr/bin/env bash
#
# Build a Docker container of Boulder (plus ancillary files), and emit both
# a .tar.gz and a .deb in the current directory, containing Boulder plus the
# ancillary files.
#

set -ex

if [ -z "${GO_VERSION}" ] ; then
  echo "GO_VERSION not set"
  exit 1
fi

COMMIT_ID="$(git rev-parse --short=8 HEAD)"
VERSION="${GO_VERSION}.$(date +%s)"

# Detect architecture to build for (allow override via DOCKER_DEFAULT_PLATFORM)
if [ -n "${DOCKER_DEFAULT_PLATFORM}" ]; then
    PLATFORM="${DOCKER_DEFAULT_PLATFORM}"
else
    case "$(uname -m)" in
        "x86_64") PLATFORM="linux/amd64" ;;
        "aarch64"|"arm64") PLATFORM="linux/arm64" ;;
        *) echo "Unsupported architecture: $(uname -m)" && exit 1 ;;
    esac
fi

# Extract architecture from platform
case "$PLATFORM" in
    "linux/amd64") ARCH="amd64" ;;
    "linux/arm64") ARCH="arm64" ;;
    *) echo "Unsupported platform: ${PLATFORM}" && exit 1 ;;
esac

# Define single tag to avoid collisions and redundancy
TAG="boulder:${VERSION}-${ARCH}"

# Create platform-specific image
docker buildx build \
    --file Containerfile \
    --platform "$PLATFORM" \
    --build-arg "COMMIT_ID=${COMMIT_ID}" \
    --build-arg "GO_VERSION=${GO_VERSION}" \
    --build-arg "VERSION=${VERSION}" \
    --tag "${TAG}" \
    --load \
    .

# Create tarball
docker run "${TAG}" tar -C /opt/boulder -cpz . > "./boulder-${VERSION}-${COMMIT_ID}.${ARCH}.tar.gz"

# Create .deb package
docker run -v .:/boulderrepo \
    -e "COMMIT_ID=${COMMIT_ID}" \
    -e "VERSION=${VERSION}" \
    -e "ARCH=${ARCH}" \
    "${TAG}" \
    /boulderrepo/tools/make-deb.sh
