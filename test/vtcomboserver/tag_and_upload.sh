#!/bin/bash

set -feuxo pipefail

cd $(dirname $0)

DATESTAMP=$(date +%Y-%m-%d)
DOCKER_REPO="letsencrypt/boulder-vtcomboserver"
VITESS_TAG=v23.0.0

echo "Please login to allow push to DockerHub"
docker login

# Usage: build_and_push_image $VITESS_TAG
build_and_push_image() {
  VITESS_TAG="$1"
  TAG_NAME="${DOCKER_REPO}:vitess${VITESS_TAG}_${DATESTAMP}"
  echo "Building boulder-vtcomboserver image ${TAG_NAME}"

  # build, tag, and push the image.
  docker buildx build \
    --build-arg "VITESS_TAG=${VITESS_TAG}" \
    --progress plain \
    --push \
    --tag "${TAG_NAME}" \
    --platform "linux/amd64" \
    .
}

build_and_push_image $VITESS_TAG
