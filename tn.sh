#!/usr/bin/env bash
#
# Outer wrapper for invoking test.sh with config-next inside docker-compose.
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

exec docker compose -f docker-compose.yml -f docker-compose.next.yml run boulder ./test.sh "$@"
