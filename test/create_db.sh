#!/bin/bash
set -o errexit
cd $(dirname $0)/..
source test/db-common.sh

# posix compliant escape sequence
esc=$'\033' 
aesc="${esc}["

function print_heading() {
  echo
  echo -e "${aesc}0;34;1m"$1"${aesc}0m"
}

function get_migrations() {
  migrations=( $(find "$dbpath"/migrations -mindepth 1 -maxdepth 1 -not -path '*/\.*'  2> /dev/null | sort) )
}

function create_empty_db() {
  create_script="drop database if exists \`${db}\`; create database if not exists \`${db}\`;"
  mysql $dbconn -e "$create_script" || die "unable to create ${db}"
  echo "Created empty "$db" database"
}

function get_container_version() {
  container_version="$(goose -path="$dbpath" -env="$dbenv" dbversion | sed 's/goose: dbversion //')"
}

function apply_migrations() {
  if [ ! -z "${migrations[@]+x}" ]
  then
    goose -path="$dbpath" -env=$dbenv up || die "unable to migrate "${db}" with "$dbpath""
  else
    echo "no migrations at "$dbpath""
  fi
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
  db="boulder_sa_${dbenv}"

  print_heading "Checking if "$db" exists"
  if mysql $dbconn -e 'show databases;' | grep $db > /dev/null; then
    echo ""$db" already exists - skipping create"
  else
    echo ""$db" doesn't exist - creating"
    create_empty_db
  fi

  # determine which db_path to use
  if [[ "$BOULDER_CONFIG_DIR" = "test/config-next" ]]
  then
    dbpath="./sa/_db-next/"
    migrations="./sa/_db-next/migrations"
  else
    dbpath="./sa/_db/"
    migrationspath="./sa/_db/migrations"
  fi

  # populate list of migration files for $dbpath
  get_migrations

  # goose up to the latest schema present
  apply_migrations

  # latest schema is the last in the array of 
  latest_schema="$(basename -- "${migrations[-1]}")"

  # latest version is the timestamp contained in the first 14 characters
  # of the latest filename
  latest_version="${latest_schema:0:14}"
  
  # get the version of the db running in the container
  get_container_version

  # if the container_version does not match the latest schema, trigger
  # recreate
  if [ $latest_version != $container_version ]; then
    print_heading "Detected schema mismatch"
    echo "dropping and recreating from schema at "$migrationspath""
    create_empty_db
    apply_migrations
  fi

  # With MYSQL_CONTAINER, patch the GRANT statements to
  # use 127.0.0.1, not localhost, as MySQL may interpret
  # 'username'@'localhost' to mean only users for UNIX
  # socket connections. Use '-f' to ignore errors while
  # we have migrations that haven't been applied but
  # add new tables (TODO(#2931): remove -f).
  USERS_SQL=test/sa_db_users.sql
  if [[ ${MYSQL_CONTAINER} ]]; then
    sed -e "s/'localhost'/'%'/g" < ${USERS_SQL} | \
      mysql $dbconn -D $db -f || die "unable to add users to ${db}"
  else
    sed -e "s/'localhost'/'127.%'/g" < $USERS_SQL | \
      mysql $dbconn -D $db -f < $USERS_SQL || die "unable to add users to ${db}"
  fi
  echo "added users to ${db}"
done

echo
echo "database setup complete"
