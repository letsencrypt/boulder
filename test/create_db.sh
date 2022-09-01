#!/usr/bin/env bash
set -o errexit
cd $(dirname $0)/..


# If you modify DBS or ENVS, you must also modify the corresponding keys in
# sa/_db/dbconfig.yml, see: https://github.com/rubenv/sql-migrate#readme

DBS="boulder_sa
incidents_sa"

ENVS="test
integration"

# /path/to/boulder/repo
root_dir=$(dirname $(dirname $(readlink -f "$0")))

# posix compliant escape sequence
esc=$'\033'"["
res="${esc}0m"

function print_heading() {
  echo
  # newline + bold magenta
  echo -e "${esc}0;34;1m${1}${res}"
}

function exit_err() {
  if [ ! -z "$1" ]
  then
    echo $1 > /dev/stderr
  fi
  exit 1
}

function create_empty_db() {
  local db="${1}"
  local dbconn="${2}"
  create_script="drop database if exists \`${db}\`; create database if not exists \`${db}\`;"
  mysql ${dbconn} -e "${create_script}" || exit_err "unable to create ${db}"
}

# set db connection for if running in a separate container or not
dbconn="-u root"
if [[ $MYSQL_CONTAINER ]]
then
	dbconn="-u root -h boulder-mysql --port 3306"
fi

# MariaDB sets the default binlog_format to STATEMENT,
# which causes warnings that fail tests. Instead set it
# to the format we use in production, MIXED.
mysql ${dbconn} -e "SET GLOBAL binlog_format = 'MIXED';"

# MariaDB sets the default @@max_connections value to 100. The SA alone is
# configured to use up to 100 connections. We increase the max connections here
# to give headroom for other components (ocsp-updater for example).
mysql ${dbconn} -e "SET GLOBAL max_connections = 500;"

for db in $DBS; do
  for env in $ENVS; do
    dbname="${db}_${env}"
    print_heading "${dbname}"
    create_empty_db "${dbname}" "${dbconn}"

    if [[ "${BOULDER_CONFIG_DIR}" == "test/config-next" ]]
    then
      dbpath="./sa/_db-next"
    else
      dbpath="./sa/_db"
    fi

    # sql-migrate will default to ./dbconfig.yml and treat all configured dirs
    # as relative.
    cd "${dbpath}"
    sql-migrate up -env="${dbname}" || exit_err "unable to migrate ${dbname} with migrations at ${dbpath}/${db}"

    USERS_SQL="../_db-users/${db}.sql"
    if [[ ${MYSQL_CONTAINER} ]]
    then
      sed -e "s/'localhost'/'%'/g" < ${USERS_SQL} | \
        mysql ${dbconn} -D "${dbname}" -f || exit_err "unable to add users to ${dbname}"
    else
      sed -e "s/'localhost'/'127.%'/g" < $USERS_SQL | \
        mysql ${dbconn} -D "${dbname}" -f < $USERS_SQL || exit_err "unable to add users to ${dbname}"
    fi
    echo "Added users from ${USERS_SQL} to ${dbname}"
    
    # return to the root directory
    cd "${root_dir}"
  done
done

echo
echo "database setup complete"
