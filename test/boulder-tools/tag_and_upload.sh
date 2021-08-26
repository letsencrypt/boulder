#!/bin/bash -e

cd $(dirname $0)

DATESTAMP=$(date +%Y-%m-%d)
DOCKER_REPO="letsencrypt/boulder-tools"

GO_VERSIONS=( "1.16.6" "1.17" )

# Build a tagged image for each GO_VERSION
for GO_VERSION in "${GO_VERSIONS[@]}"
do
  TAG_NAME="$DOCKER_REPO:go${GO_VERSION}_${DATESTAMP}"
  echo "Building boulder-tools image $TAG_NAME"

  # Build the docker image using the templated Dockerfile, tagging it with
  # TAG_NAME
  docker build . \
    -t $TAG_NAME \
    --build-arg "GO_VERSION=${GO_VERSION}"
done

# Log in once now that images are ready to upload
echo "Images ready, please login to allow Dockerhub push"
docker login

# Upload a tagged image for each GO_VERSION
for GO_VERSION in "${GO_VERSIONS[@]}"
do
  TAG_NAME="$DOCKER_REPO:go${GO_VERSION}_${DATESTAMP}"
  echo "Pushing ${TAG_NAME} to Dockerhub"
  docker push ${TAG_NAME}
done

# TODO(@cpu): Figure out a `sed` for updating the date in `docker-compose.yml`'s
# `image` lines with $DATESTAMP
