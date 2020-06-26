#!/bin/bash

set -e -u

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Start rsyslog. Note: Sometimes for unknown reasons /var/run/rsyslogd.pid is
# already present, which prevents the whole container from starting. We remove
# it just in case it's there.
rm -f /var/run/rsyslogd.pid
service rsyslog start

wait_tcp_port() {
    local host="$1" port="$2"

    # see http://tldp.org/LDP/abs/html/devref1.html for description of this syntax.
    local max_tries="120"
    for n in `seq 1 $max_tries` ; do
      if exec 6<>/dev/tcp/$host/$port; then
        break
      else
        echo "$(date) - still trying to connect to $host:$port"
        sleep 1
      fi
      if [ "$n" -eq "$max_tries" ]; then
        echo "unable to connect"
        exit 1
      fi
    done
    exec 6>&-
    echo "Connected to $host:$port"
}
# make sure we can reach the mysqldb
wait_tcp_port boulder-mysql 3306

# create the database
MYSQL_CONTAINER=1 $DIR/create_db.sh

if [[ $# -eq 0 ]]; then
    exec python3 ./start.py
fi

exec $@
