#!/usr/bin/env bash

docker buildx build \
    --build-arg COMMIT_ID=$(git rev-parse --short=8 HEAD) \
    --build-arg GO_VERSION=1.24.5 \
    --tag boulder:$(git rev-parse --short=8 HEAD) \
    --tag boulder \
    .

docker run boulder tar -C /opt/boulder -cpz > boulder.tar.gz .
