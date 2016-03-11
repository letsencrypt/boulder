#!/bin/bash
set -o xtrace

if [ -z "$VERSION" ]; then
    VERSION="1.0.0"
fi
if [ -z "$COMMIT_ID" ]; then
    COMMIT_ID=$(git rev-parse --short HEAD)
fi
if [ -z "$ARCHIVEDIR" ]; then
    ARCHIVEDIR=$(pwd)
fi

docker build -f Dockerfile-build -t boulder-build .
docker rm builder
docker run --name builder boulder-build
docker cp builder:/tmp/boulder-$VERSION-$COMMIT_ID.x86_64.rpm $ARCHIVEDIR/
docker rm builder
