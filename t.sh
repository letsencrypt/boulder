#!/usr/bin/env bash
#
# Outer wrapper for invoking test.sh inside docker-compose.
#

set -o errexit

if type realpath >/dev/null 2>&1 ; then
  cd "$(realpath -- $(dirname -- "$0"))"
fi

# Generate the test keys and certs necessary for the integration tests.
docker compose run --rm bsetup

# If we're running on a terminal (-t 0), have docker create a pseudo-tty
# (-it) so Ctrl-C gets passed to all PIDs in the foreground process group.
TERMFLAGS=
if [ -t 0 ] ; then
  TERMFLAGS="-it"
fi

exec docker compose run -it -e USE_VITESS --rm --name boulder_tests boulder ./test.sh "$@"
