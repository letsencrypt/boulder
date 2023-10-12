#!/bin/bash

set -feuxo pipefail

cd $(dirname $0)

DATESTAMP=$(date +%Y-%m-%d)
DOCKER_REPO="letsencrypt/boulder-tools"

# These versions are only built for platforms that we run in CI.
# When updating these GO_CI_VERSIONS, please also update
# .github/workflows/release.yml,
# .github/workflows/try-release.yml if appropriate,
# and .github/workflows/boulder-ci.yml with the new container tag.
GO_CI_VERSIONS=( "1.21.1" "1.21.3" )
# These versions are built for both platforms that boulder devs use.
# When updating GO_DEV_VERSIONS, please also update
# ../../docker-compose.yml's default Go version.
GO_DEV_VERSIONS=( "1.21.3" )

echo "Please login to allow push to DockerHub"
docker login

# Usage: build_and_push_image $GO_VERSION $PLATFORMS
build_and_push_image() {
  GO_VERSION="$1"
  PLATFORMS="$2"
  TAG_NAME="${DOCKER_REPO}:go${GO_VERSION}_${DATESTAMP}"
  echo "Building boulder-tools image ${TAG_NAME}"

  # build, tag, and push the image.
  docker buildx build \
    --build-arg "GO_VERSION=${GO_VERSION}" \
    --progress plain \
    --push \
    --tag "${TAG_NAME}" \
    --platform "${PLATFORMS}" \
    .
}

for GO_VERSION in "${GO_CI_VERSIONS[@]}"
do
  build_and_push_image $GO_VERSION linux/amd64
done

for GO_VERSION in "${GO_DEV_VERSIONS[@]}"
do
  build_and_push_image $GO_VERSION linux/amd64,linux/arm64
done

# This needs to work with both GNU sed and BSD sed
echo "Updating container build timestamp in docker-compose.yml"
sed -i.bak -E "s|BOULDER_TOOLS_TAG:-go([0-9.]+)_([0-9-]+)}$|BOULDER_TOOLS_TAG:-go${GO_DEV_VERSIONS[0]}_${DATESTAMP}}|g" ../../docker-compose.yml
rm -f ../../docker-compose.yml.bak
