#!/bin/bash

# A script to make it easier to parallelize the build by building make
# conditionally.

set -o errexit

if [ "${TRAVIS}" != "true" ]; then
  echo "Not to be run outside of TravisCI" > /dev/stderr
  exit 1
fi

if [ "${RUN_MAKE}" == "1" ]; then
  make -j4 # Travis has 2 cores per build instance
fi
