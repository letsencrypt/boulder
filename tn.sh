#!/usr/bin/env bash
#
# Outer wrapper for invoking test.sh with config-next inside docker-compose.
#

if type realpath >/dev/null 2>&1 ; then
  cd "$(realpath -- $(dirname -- "$0"))"
fi

source ./tools/t-helper.sh

exec ${_compose} -f docker-compose.yml -f docker-compose.next.yml run boulder ./test.sh "$@"
