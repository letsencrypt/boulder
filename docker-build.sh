#!/bin/bash
set -o xtrace
set -e

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
if [ -n "$(docker ps -a -f name=builder -q)" ]; then
    docker rm builder
fi
docker run --name builder boulder-build
docker cp builder:$ARCHIVEDIR/boulder-$VERSION-$COMMIT_ID.x86_64.rpm $ARCHIVEDIR/
docker rm builder
