#!/usr/bin/env bash

# -e Stops execution in the instance of a command or pipeline error
# -u Treat unset variables as an error and exit immediately
set -eu

touch /test/proxysql/proxysql.log
exec proxysql -f --idle-threads -c /test/proxysql/proxysql.cnf --initial 2>&1 | tee -a /test/proxysql/proxysql.log
