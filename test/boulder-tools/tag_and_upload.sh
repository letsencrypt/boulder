#!/bin/bash -e

cd $(dirname $0)

DATESTAMP=$(date +%Y-%m-%d)
TAG_NAME="letsencrypt/boulder-tools:$DATESTAMP"

echo "Building boulder-tools image $TAG_NAME"
docker build . -t $TAG_NAME --no-cache

echo "Image ready."
docker login

echo "Pushing $TAG_NAME to Dockerhub"
docker push $TAG_NAME

sed -i "s,image: letsencrypt/boulder-tools.*,image: $TAG_NAME," ../../docker-compose.yml
