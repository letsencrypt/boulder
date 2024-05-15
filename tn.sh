#!/usr/bin/env bash
#
# Outer wrapper for invoking test.sh with config-next inside docker-compose.
#

if type realpath >/dev/null 2>&1 ; then
  cd "$(realpath -- $(dirname -- "$0"))"
fi

# Generate the test keys and certs necessary for the integration tests.
docker compose up bsetup

# Use a predictable name for the container so we can grab the logs later
# for use when testing logs analysis tools.
docker rm boulder_tests
exec docker compose -f docker-compose.yml -f docker-compose.next.yml run boulder ./test.sh "$@"
