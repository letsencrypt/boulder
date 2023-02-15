#!/bin/bash

set -feuxo pipefail

DIR=$(pwd)
cd $(dirname $0)

DATESTAMP=$(date +%Y-%m-%d)
DOCKER_REPO="letsencrypt/boulder-tools"

# When updating these GO_VERSIONS, please also update
# .github/workflows/release.yml,
# .github/workflows/try-release.yml if appropriate,
# .github/workflows/boulder-ci.yml with the new container tag.
GO_VERSIONS=( "1.19.5" "1.19.6" "1.20.1" )

echo "Please login to allow push to DockerHub"
docker login

# Build and push a tagged image for each GO_VERSION.
for GO_VERSION in "${GO_VERSIONS[@]}"
do
  TAG_NAME="${DOCKER_REPO}:go${GO_VERSION}_${DATESTAMP}"
  echo "Building boulder-tools image ${TAG_NAME}"

  # build, tag, and push the image.
  docker buildx build --build-arg "GO_VERSION=${GO_VERSION}" \
    --progress plain \
    --push --tag "${TAG_NAME}" \
    --platform=linux/amd64,linux/arm64 .
done

# This needs to work with both GNU sed and BSD sed
echo "Updating container build timestamp in docker-compose.yml"
sed -i.bak -E "s|BOULDER_TOOLS_TAG:-go([0-9.]+)_([0-9-]+)}$|BOULDER_TOOLS_TAG:-go\1_${DATESTAMP}}|" "${DIR}/docker-compose.yml"
rm -f ${DIR}/docker-compose.yml.bak
