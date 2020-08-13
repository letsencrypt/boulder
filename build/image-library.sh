#!/bin/bash

# calculate_module_names Calculates module names based on the Dockerfile filenames
function calculate_module_names() {
  dockerfile_names=($(find build/ -maxdepth 1 -type f -regex 'build/Dockerfile\.[a-z0-9-]*' -exec basename {} \;))
  module_names=()
  for dockerfile_name in "${dockerfile_names[@]}"; do
    module_name="${dockerfile_name##*.}"
    echo "calculated module name ${module_name}"
    module_names+=(${module_name})
  done
  MODULE_NAMES=("${module_names[@]}")
}

# calculate_image_prefix Calculates Docker image prefix based on registry settings
function calculate_image_prefix() {
  # locally calculated variables
  docker_registry_prefix=""

  # prepare Docker registry prefix if any
  if [[ ! -z ${DOCKER_REGISTRY} ]]; then
    docker_registry_prefix="${DOCKER_REGISTRY}/"
  fi
  DOCKER_REGISTRY_PREFIX=${docker_registry_prefix}
}
