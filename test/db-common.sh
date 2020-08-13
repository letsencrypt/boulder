# Common variables used by Goose-related scripts.
function die() {
  if [ ! -z "$1" ]; then
    echo $1 > /dev/stderr
  fi
  exit 1
}

DBENVS="test
integration"
MYSQL_HOST=${MYSQL_HOST:-boulder-mysql}
MYSQL_PORT=${MYSQL_PORT:-3306}
