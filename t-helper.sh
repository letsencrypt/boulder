#!/usr/bin/env bash
#
# Helper script to do some environment setup for our t shell test files
#

# Check if the docker binary is on the PATH and usable
command -v docker > /dev/null 2>&1
if [ ${?} -ne 0 ]; then
    echo "You need to install docker."
    exit 1
fi

# Check for existence of the "docker compose" plugin available only on
# Linux systems. Otherwise, use the docker-compose standalone binary.
if docker compose version 2>&1 > /dev/null; then
    _compose="docker compose"
else
    _compose="docker-compose"
fi
