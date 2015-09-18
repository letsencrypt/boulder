# Common variables used by Goose-related scripts.
set -o errexit
set -o xtrace

function die() {
  if [ ! -z "$1" ]; then
    echo $1 > /dev/stderr
  fi
  exit 1
}

SERVICES="ca
sa
policy"
DBENVS="development
test
integration"
