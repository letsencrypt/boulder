#!/bin/bash

set -feuxo pipefail

cd $(dirname $0)

DATESTAMP=$(date +%Y-%m-%d)
DOCKER_REPO="letsencrypt/boulder-sunlight"
SUNLIGHT_TAG=v0.9.0

echo "Please login to allow push to DockerHub"
docker login

# Usage: build_and_push_image $SUNLIGHT_TAG
build_and_push_image() {
  SUNLIGHT_TAG="$1"
  TAG_NAME="${DOCKER_REPO}:sunlight${SUNLIGHT_TAG}_${DATESTAMP}"
  echo "Building boulder-sunlight image ${TAG_NAME}"

  # build, tag, and push the image.
  docker buildx build \
    --build-arg "SUNLIGHT_TAG=${SUNLIGHT_TAG}" \
    --progress plain \
    --push \
    --tag "${TAG_NAME}" \
    --platform "linux/amd64" \
    .
}

build_and_push_image $SUNLIGHT_TAG
