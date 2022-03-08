#!/bin/bash

set -feuxo pipefail

cd $(dirname $0)

DATESTAMP=$(date +%Y-%m-%d)
DOCKER_REPO="letsencrypt/boulder-tools"

GO_VERSIONS=( "1.17.7" "1.18beta2" )

echo "Please login to allow push to DockerHub"
docker login

# Create a docker buildx node for cross-compilation if it doesn't already exist.
if ! docker buildx ls | grep -q "cross.*linux/arm64" ||
   ! docker buildx ls | grep -q "cross.*linux/amd64"
then
  cat 2>&1 <<<EOF
Docker on this host cannot cross-build. Run:

docker buildx ls

It should show an entry like:
cross0  unix:///var/run/docker.sock running linux/amd64, linux/386, linux/arm64, linux/riscv64, linux/ppc64le, linux/s390x, linux/mips64le, linux/mips64, linux/arm/v7, linux/arm/v6

If not, run:

docker buildx create --use --name=cross

Also, you may need to install some qemu packages. For instance:

https://www.stereolabs.com/docs/docker/building-arm-container-on-x86/

sudo sudo apt-get install qemu binfmt-support qemu-user-static
EOF
  exit 1
fi

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

# TODO(@cpu): Figure out a `sed` for updating the date in `docker-compose.yml`'s
# `image` lines with $DATESTAMP
