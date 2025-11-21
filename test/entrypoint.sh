#!/usr/bin/env bash

set -e -u

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Start rsyslog. Note: Sometimes for unknown reasons /var/run/rsyslogd.pid is
# already present, which prevents the whole container from starting. We remove
# it just in case it's there.
rm -f /var/run/rsyslogd.pid
rsyslogd

# make sure we can reach mariadb and proxysql
./test/wait-for-it.sh boulder-mariadb 3306
./test/wait-for-it.sh boulder-proxysql 6033

# make sure we can reach vitess
./test/wait-for-it.sh boulder-vitess 33577

# make sure we can reach pkilint
./test/wait-for-it.sh bpkimetal 8080

# create the databases
( cd sa/db && ln -sf dbconfig.mariadb.yml dbconfig.yml )
MYSQL_CONTAINER=1 \
BACKEND_LABEL="MariaDB (via ProxySQL)" \
MYSQL_HOST="boulder-mariadb" \
MYSQL_PORT=3306 \
SKIP_CREATE=0 \
SKIP_USERS=0 \
"$DIR/create_db.sh"

( cd sa/db && ln -sf dbconfig.mysql8.yml dbconfig.yml )
MYSQL_CONTAINER=1 \
BACKEND_LABEL="Vitess" \
MYSQL_HOST="boulder-vitess" \
MYSQL_PORT=33577 \
SKIP_CREATE=1 \
SKIP_USERS=1 \
"$DIR/create_db.sh"

( cd sa/db && ln -sf dbconfig.mariadb.yml dbconfig.yml )

if [[ $# -eq 0 ]]; then
    exec python3 ./start.py
fi

exec "$@"
