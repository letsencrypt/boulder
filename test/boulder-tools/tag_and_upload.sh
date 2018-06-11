#!/bin/bash -e

cd $(dirname $0)

DATESTAMP=$(date +%Y-%m-%d)
BASE_TAG_NAME="letsencrypt/boulder-tools"
GO_VERSIONS=( "1.10.2" "1.10.3" )

# Build a tagged image for each GO_VERSION
for GO_VERSION in "${GO_VERSIONS[@]}"
do
  TAG_NAME="$BASE_TAG_NAME-go$GO_VERSION:$DATESTAMP"
  echo "Building boulder-tools image $TAG_NAME"

  # NOTE(@cpu): Generating DOCKERFILE's on disk with the %%GO_VERSION%%
  # templated out by `sed` is required because only Docker v17+ supports env var
  # interpolation in Dockerfile `FROM` directives. This version isn't commonly
  # packaged so we rely on this technique for the time being. Similarly, it
  # would be cleaner if we could just output the `sed` directly to the `docker
  # build` stdin but that requires Docker 17+ too! :'(
  DOCKERFILE="golang.$GO_VERSION.Dockerfile"
  sed -r \
    -e 's!%%GO_VERSION%%!'"$GO_VERSION"'!g' \
    "Dockerfile.tmpl" > "$DOCKERFILE"

  # Build the docker image using the templated Dockerfile, tagging it with
  # TAG_NAME
  docker build . \
    -t $TAG_NAME \
    --no-cache \
    -f "$DOCKERFILE"

  # Clean up the temp. Dockerfile
  rm "$DOCKERFILE"
done

# Log in once now that images are ready to upload
echo "Images ready, please login to allow Dockerhub push"
docker login

# Upload a tagged image for each GO_VERSION
for GO_VERSION in "${GO_VERSIONS[@]}"
do
  TAG_NAME="$BASE_TAG_NAME-go$GO_VERSION:$DATESTAMP"
  echo "Pushing $TAG_NAME to Dockerhub"
  docker push $TAG_NAME
done

# TODO(@cpu): Figure out a `sed` for updating the date in `docker-compose.yml`'s
# `image` lines with $DATESTAMP
