#!/bin/bash

set -e

# eg. release-2020-04-13
BOULDER_VERSION=${BOULDER_VERSION:-latest}
# eg. localhost:5000
DOCKER_REGISTRY=${DOCKER_REGISTRY:-}
PROJECT_ID=${PROJECT_ID:-letsencrypt}

# we'll need docker for this
which docker 2>&1 > /dev/null

# use image functions
source $(dirname $0)/image-library.sh
# calculate module names
calculate_module_names
# calculate image prefix
calculate_image_prefix

# build the images
for module_name in "${MODULE_NAMES[@]}"; do
  docker build -t ${DOCKER_REGISTRY_PREFIX}${PROJECT_ID}/boulder-${module_name}:${BOULDER_VERSION} -f build/Dockerfile.${module_name} .
done
