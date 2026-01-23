#!/usr/bin/env bash
set -o errexit
cd $(dirname $0)/..


# If you modify DBS or ENVS, you must also modify the corresponding keys in
# sa/db/dbconfig.yml, see: https://github.com/rubenv/sql-migrate#readme

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
  mysql ${dbconn} -e "${create_script}" || exit_err "unable to create ${db} on ${dbconn}"
}

dbconn="-u root -h ${DB_HOST} --port ${DB_PORT}"

if ! mysql ${dbconn} -e "select 1" >/dev/null 2>&1; then
  exit_err "unable to connect to ${DB_HOST}:${DB_PORT}"
fi

if [[ ${SKIP_CREATE} -eq 0 ]]
then
  # MariaDB sets the default binlog_format to STATEMENT,
  # which causes warnings that fail tests. Instead set it
  # to the format we use in production, MIXED.
  mysql ${dbconn} -e "SET GLOBAL binlog_format = 'MIXED';"

  # MariaDB sets the default @@max_connections value to 100. The SA alone is
  # configured to use up to 100 connections. We increase the max connections here
  # to give headroom for other components.
  mysql ${dbconn} -e "SET GLOBAL max_connections = 500;"
fi

for db in $DBS; do
  for env in $ENVS; do
    dbname="${db}_${env}"
    print_heading "${dbname}"
    if [[ ${SKIP_CREATE} -eq 0 ]]
    then
      if mysql ${dbconn} -e 'show databases;' | grep -q "${dbname}"
      then
        echo "Already exists - skipping create"
      else
        echo "Doesn't exist - creating"
        create_empty_db "${dbname}" "${dbconn}"
      fi
    else
      echo "Skipping database create for ${dbname}"
    fi

    if [[ "${BOULDER_CONFIG_DIR}" == "test/config-next" ]]
    then
      dbpath="./sa/db-next"
    else
      dbpath="./sa/db"
    fi

    # sql-migrate will default to ./dbconfig.yml and treat all configured dirs
    # as relative.
    cd "${dbpath}"
    r=`sql-migrate up -config="${DB_CONFIG_FILE}" -env="${dbname}" | xargs -0 echo`
    if [[ "${r}" == "Migration failed"* ]]
    then
      echo "sql-migrate: ${r}"
      echo "Try \`docker compose down --volumes\` and running again"
      exit 1
    else
      echo "sql-migrate: ${r}"
    fi

    USERS_SQL="../db-users/${db}.sql"
    if [[ ${SKIP_USERS} -eq 1 ]]
    then
      echo "Skipping user grants for ${dbname}"
    else
      sed -e "s/'localhost'/'%'/g" < "${USERS_SQL}" | \
        mysql ${dbconn} -D "${dbname}" -f || exit_err "Unable to add users from ${USERS_SQL}"
      echo "Added users from ${USERS_SQL}"
    fi

    # return to the root directory
    cd "${root_dir}"
  done
done

echo
echo "database setup complete"
