#!/bin/bash -e

DATESTAMP=$(date +%Y-%m-%d)
TAG_NAME="letsencrypt/boulder-tools:$DATESTAMP"

echo "Building boulder-tools image $TAG_NAME"
docker build . -t $TAG_NAME

echo "Image ready."
docker login

echo "Pushing $TAG_NAME to Dockerhub"
docker push $TAG_NAME
