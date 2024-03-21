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
  ${dbconn} -c "CREATE DATABASE ${db}" || exit_err "unable to create ${db}"
}

# set db connection for if running in a separate container or not
export PGPASSWORD=VV5PugWx0QQyVHHmdwvSu+RW60U
dbconn="psql -U postgres -h 10.77.77.2"

for db in $DBS; do
  for env in $ENVS; do
    dbname="${db}_${env}"
    print_heading "${dbname}"
    if ${dbconn} -t -c "SELECT datname FROM pg_database WHERE datname='${dbname}';" | grep "${dbname}" > /dev/null; then
      echo "Already exists - skipping create"
    else
      echo "Doesn't exist - creating"
      create_empty_db "${dbname}" "${dbconn}"
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
    r=`sql-migrate up -env="${dbname}" | xargs -0 echo`
    if [[ "${r}" == "Migration failed"* ]]
    then
      echo "Migration failed - dropping and recreating"
      create_empty_db "${dbname}" "${dbconn}"
      sql-migrate up -env="${dbname}" || exit_err "Migration failed after dropping and recreating"
    else
      echo "${r}"
    fi

    USERS_SQL="../db-users/${db}.psql"
    ${dbconn} -d "${dbname}" < $USERS_SQL || exit_err "Unable to add users from ${USERS_SQL}"
    echo "Added users from ${USERS_SQL}"

    # return to the root directory
    cd "${root_dir}"
  done
done

echo
echo "database setup complete"
