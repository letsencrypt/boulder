#!/usr/bin/env bash

set -e -u

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Start rsyslog. Note: Sometimes for unknown reasons /var/run/rsyslogd.pid is
# already present, which prevents the whole container from starting. We remove
# it just in case it's there.
rm -f /var/run/rsyslogd.pid
rsyslogd

DB_URL_FILES=(
  badkeyrevoker_dburl
  cert_checker_dburl
  incidents_dburl
  revoker_dburl
  sa_dburl
  sa_ro_dburl
)

configure_database_endpoints() {
  DB_STYLE="proxysql"
  export DB_ADDR="boulder-proxysql:6033"

  if [[ "${USE_VITESS}" == "true" ]]
  then
    DB_STYLE="vitess"
    export DB_ADDR="boulder-vitess:33577"
  fi

  SECRETS_DIR="${BOULDER_CONFIG_DIR}/${DB_STYLE}"

  # Configure DBURL symlinks
  rm -f test/secrets/*_dburl || true
  for file in ${DB_URL_FILES:+${DB_URL_FILES[@]+"${DB_URL_FILES[@]}"}}
  do
    ln -sf "../../${SECRETS_DIR}/${file}" "test/secrets/${file}"
  done
}

# Defaults to MariaDB/ProxySQL unless USE_VITESS is true.
configure_database_endpoints

# make sure we can reach mariadb and proxysql
./test/wait-for-it.sh boulder-mariadb 3306
./test/wait-for-it.sh boulder-proxysql 6033

# make sure we can reach vitess
./test/wait-for-it.sh boulder-vitess 33577

# make sure we can reach pkilint
./test/wait-for-it.sh bpkimetal 8080

if [[ $# -eq 0 ]]; then
    exec python3 ./start.py
fi

exec "$@"
