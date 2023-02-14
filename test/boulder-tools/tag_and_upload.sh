#!/bin/bash

set -feuxo pipefail

cd $(dirname $0)

DATESTAMP=$(date +%Y-%m-%d)
DOCKER_REPO="letsencrypt/boulder-tools"

# When updating these GO_VERSIONS, please also update
# .github/workflows/release.yml,
# .github/workflows/try-release.yml if appropriate,
# .github/workflows/boulder-ci.yml with the new container tag.
GO_VERSIONS=( "1.19.5" "1.19.6" "1.21" )

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

echo "Updating the docker-compose.yml BOULDER_TOOLS_TAG date stamp"
OLD_DATESTAMP=$(grep 'BOULDER_TOOLS_TAG' docker-compose.yml | awk -F':' '{print $4}' | awk -F'_' '{print $2}' | sed 's/}$//')
sed -i '' "s/${OLD_DATESTAMP}/${DATESTAMP}/" docker-compose.yml