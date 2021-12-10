#!/bin/bash -e

cd $(dirname $0)

DATESTAMP=$(date +%Y-%m-%d)
DOCKER_REPO="letsencrypt/boulder-tools"

GO_VERSIONS=( "1.17" "1.17.5" )

echo "Please login to allow push to DockerHub"
docker login

# Build and push a tagged image for each GO_VERSION.
for GO_VERSION in "${GO_VERSIONS[@]}"
do
  TAG_NAME="${DOCKER_REPO}:go${GO_VERSION}_${DATESTAMP}"
  echo "Building boulder-tools image ${TAG_NAME}"
  
  # create a docker buildx node for cross-compilation.
  docker buildx create --use --name=cross

  # on EXIT, delete the docker buildx node.
  trap "docker buildx rm cross" EXIT
  
  # build, tag, and push the image.
  docker buildx build --build-arg "GO_VERSION=${GO_VERSION}" \
    --push --tag "${TAG_NAME}" \
    --platform=linux/amd64,linux/arm64 .
done

# TODO(@cpu): Figure out a `sed` for updating the date in `docker-compose.yml`'s
# `image` lines with $DATESTAMP
