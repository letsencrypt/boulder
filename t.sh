#!/usr/bin/env bash
#
# Outer wrapper for invoking test.sh inside docker-compose.
#

if type realpath >/dev/null 2>&1 ; then
  cd "$(realpath -- $(dirname -- "$0"))"
fi

lastBuild=$(date -d $(docker inspect letsencrypt/boulder-tools:latest | jq -r ".[0].Created") +%s)
lastMod=$(date -d $(git log -1 --pretty="format:%cI" test/boulder-tools/) +%s)
if [ $lastBuild -le $lastMod ]
then
  docker compose build
fi

# Use a predictable name for the container so we can grab the logs later
# for use when testing logs analysis tools.
docker rm boulder_tests
exec docker compose run --name boulder_tests boulder ./test.sh "$@"
