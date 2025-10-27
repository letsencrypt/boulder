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
# Use commit timestamp for reproducible builds
COMMIT_TIMESTAMP="$(git show -s --format=%ct HEAD)"
VERSION="${GO_VERSION}.${COMMIT_TIMESTAMP}"

# Determine what architecture to build for
if [ -n "${DOCKER_DEFAULT_PLATFORM}" ]; then
    # User specified a platform override
    PLATFORM="${DOCKER_DEFAULT_PLATFORM}"
else
    # No override - detect from current machine
    MACHINE_ARCH=$(uname -m)
    case "${MACHINE_ARCH}" in
        x86_64)    PLATFORM="linux/amd64" ;; 
        aarch64)   PLATFORM="linux/arm64" ;; 
        arm64)     PLATFORM="linux/arm64" ;; 
        *) echo "Unsupported machine architecture: ${MACHINE_ARCH}" && exit 1 ;; 
    esac
fi

# Convert platform to short architecture name for file naming
case "${PLATFORM}" in
    linux/amd64) ARCH="amd64" ;; 
    linux/arm64) ARCH="arm64" ;; 
    *) echo "Unsupported platform: ${PLATFORM}" && exit 1 ;; 
esac

# Create platform-specific image
# Keep generic tags for standalone use
docker buildx build \
    --file Containerfile \
    --platform "$PLATFORM" \
    --build-arg "COMMIT_ID=${COMMIT_ID}" \
    --build-arg "GO_VERSION=${GO_VERSION}" \
    --build-arg "VERSION=${VERSION}" \
    --tag "boulder:${VERSION}-${ARCH}" \
    --tag "boulder:${VERSION}" \
    --tag "boulder" \
    --load \
    --progress=plain \
    .

# Create tarball
docker run "boulder" tar -C /opt/boulder -cpz . \
    > "./boulder-${VERSION}-${COMMIT_ID}.${ARCH}.tar.gz"

# Create .deb package
docker run -v .:/boulderrepo \
    -e "COMMIT_ID=${COMMIT_ID}" \
    -e "VERSION=${VERSION}" \
    -e "ARCH=${ARCH}" \
    "boulder" \
    /boulderrepo/tools/make-deb.sh
