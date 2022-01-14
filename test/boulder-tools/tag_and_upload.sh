#!/bin/bash -e

cd $(dirname $0)

DATESTAMP=$(date +%Y-%m-%d)
DOCKER_REPO="letsencrypt/boulder-tools"

GO_VERSIONS=( "1.17" "1.17.5" )

echo "Please login to allow push to DockerHub"
docker login

# Create a docker buildx node for cross-compilation if it doesn't already exist.
if !(docker buildx ls | grep -q "cross")
then
  docker buildx create --use --name=cross
fi

# Build and push a tagged image for each GO_VERSION.
for GO_VERSION in "${GO_VERSIONS[@]}"
do
  TAG_NAME="${DOCKER_REPO}:go${GO_VERSION}_${DATESTAMP}"
  echo "Building boulder-tools image ${TAG_NAME}"

  # build, tag, and push the image.
  docker buildx build --build-arg "GO_VERSION=${GO_VERSION}" \
    --push --tag "${TAG_NAME}" \
    --platform=linux/amd64,linux/arm64 .
done

# TODO(@cpu): Figure out a `sed` for updating the date in `docker-compose.yml`'s
# `image` lines with $DATESTAMP
