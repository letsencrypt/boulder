#!/bin/bash -ex
# Stop any running boulder containers
docker-compose stop
# Rebuild anything that has changed since the last run
docker-compose build
# Ff docker-compose run is used before using `up -d` docker will
# default to using old containers built from previous images
# (if anything has changed). `up` takes any changes in configuration
# or image into consideration when choosing which containers to
# bring back up and will recreate any that are out of date
docker-compose up -d
