#!/bin/bash
set -o xtrace

if [ -z "$VERSION"]; then
    VERSION="1.0.0"
fi
if [ -z "$COMMIT" ]; then
    COMMIT=$(git rev-parse --short HEAD)
fi

rm -r build/
mkdir build

docker build -f Dockerfile-build -t boulder-build .
docker rm builder
docker run --name builder boulder-build
docker cp builder:/tmp/boulder-$VERSION-$COMMIT.x86_64.rpm build/
docker rm builder
