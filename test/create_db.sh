#!/usr/bin/env bash
set -o errexit
cd $(dirname $0)/..

DBENVS="test
integration"

# Should point to /path/to/boulder, given that this script
# lives in the //grpc subdirectory of the boulder repo.
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
  if [ ! -z "$1" ]; then
    echo $1 > /dev/stderr
  fi
  exit 1
}

function exit_msg() {
  # complain to STDERR and exit with error
  echo "${*}" >&2
  exit 2
}

function get_migrations() {
  local db_schemas_path="${1}"
  local migrations=()
  for file in "${db_schemas_path}"/*.sql; do
    [[ -f "${file}" ]] || continue
    migrations+=("${file}")
  done
  if [[ "${migrations[@]}" ]]; then
    echo "${migrations[@]}"
  else
    exit_msg "There are no migrations at path: "\"${db_schemas_path}\"""
  fi
}

function create_empty_db() {
  local db="${1}"
  local dbconn="${2}"
  create_script="drop database if exists \`${db}\`; create database if not exists \`${db}\`;"
  mysql ${dbconn} -e "${create_script}" || exit_err "unable to create ${db}"
  echo "created empty "$db" database"
}

# set db connection for if running in a separate container or not
dbconn="-u root"
if [[ $MYSQL_CONTAINER ]]; then
	dbconn="-u root -h boulder-mysql --port 3306"
fi

# MariaDB sets the default binlog_format to STATEMENT,
# which causes warnings that fail tests. Instead set it
# to the format we use in production, MIXED.
mysql $dbconn -e "SET GLOBAL binlog_format = 'MIXED';"

# MariaDB sets the default @@max_connections value to 100. The SA alone is
# configured to use up to 100 connections. We increase the max connections here
# to give headroom for other components (ocsp-updater for example).
mysql $dbconn -e "SET GLOBAL max_connections = 500;"

for dbenv in $DBENVS; do
  db="boulder_sa"
  print_heading "Checking if ${db}_${dbenv} exists"
  if mysql ${dbconn} -e 'show databases;' | grep "${db}_${dbenv}" > /dev/null; then
    echo "${db}_${dbenv} already exists - skipping create"
  else
    echo "${db}_${dbenv} doesn't exist - creating"
    create_empty_db "${db}_${dbenv}" "${dbconn}"
  fi

  # Determine which $dbpath and $db_mig_path to use.
  if [[ "${BOULDER_CONFIG_DIR}" == "test/config-next" ]]
  then
    dbpath="./sa/_db-next"
  else
    dbpath="./sa/_db"
  fi
  db_mig_path="${dbpath}"

  # Populate an array with schema files present at $dbpath.
  # migrations=($(get_migrations "${db_mig_path}"))

  cd "${dbpath}"
  pwd
  ls -lah

  sql-migrate up -env="${db}_${dbenv}" || exit_err "unable to migrate ${db} with ${dbpath}"

  # The (actual) latest migration should always be the last file or
  # symlink at $db_mig_path.
  # latest_mig_path_filename="$(basename -- "${migrations[-1]}")"

  # Goose's dbversion is the timestamp (first 14 characters) of the file
  # that it last migrated to. We can figure out which goose dbversion we
  # should be on by parsing the timestamp of the latest file at
  # $db_mig_path.
  # latest_db_mig_version="${latest_mig_path_filename:0:14}"
  
  # Ask Goose the timestamp (dbversion) our database is currently
  # migrated to.
  # goose_dbversion="$(goose -path=${dbpath} -env=${dbenv} dbversion | sed 's/goose: dbversion //')"

  # If the $goose_dbversion does not match the $latest_in_db_mig_path,
  # trigger recreate
  # if [[ "${latest_db_mig_version}" != "${goose_dbversion}" ]]; then
  #   print_heading "Detected latest migration version mismatch"
  #   echo "dropping and recreating from migrations at ${db_mig_path}"
  #   create_empty_db "${db}" "${dbconn}"
  #   apply_migrations "${migrations}" "${dbpath}" "${dbenv}" "${db}"
  # fi

  # With MYSQL_CONTAINER, patch the GRANT statements to
  # use 127.0.0.1, not localhost, as MySQL may interpret
  # 'username'@'localhost' to mean only users for UNIX
  # socket connections. Use '-f' to ignore errors while
  # we have migrations that haven't been applied but
  # add new tables (TODO(#2931): remove -f).

  # Return to the root of the repo.
  cd "${root_dir}"

  USERS_SQL=test/sa_db_users.sql
  if [[ ${MYSQL_CONTAINER} ]]; then
    sed -e "s/'localhost'/'%'/g" < ${USERS_SQL} | \
      mysql $dbconn -D "${db}_${dbenv}" -f || exit_err "unable to add users to ${db}_${dbenv}"
  else
    sed -e "s/'localhost'/'127.%'/g" < $USERS_SQL | \
      mysql $dbconn -D "${db}_${dbenv}" -f < $USERS_SQL || exit_err "unable to add users to ${db}_${dbenv}"
  fi
  echo "added users to ${db}_${dbenv}"
done

echo
echo "database setup complete"
