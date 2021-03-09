#!/bin/bash
set -o errexit
cd $(dirname $0)/..
source test/db-common.sh

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

  create_script="drop database if exists \`${db}\`; create database if not exists \`${db}\`;"

  mysql $dbconn -e "$create_script" || die "unable to create ${db}"

  echo "created empty ${db} database"

  if [[ "$BOULDER_CONFIG_DIR" = "test/config" ]]; then
    migrations_dir="./sa/_db"
  else
    migrations_dir="./sa/_db-next/"
  fi

  # Goose exits non-zero if there are no migrations to apply with the error
  # message:
  #   "2016/09/26 15:43:38 no valid version found"
  # so we only want to run goose with the migrations_dir if there is a migrations
  # directory present with at least one migration
  if [ $(find "$migrations_dir/migrations" -maxdepth 0 -type d -not -empty 2>/dev/null) ]; then
    goose -path=${migrations_dir} -env=$dbenv up || die "unable to migrate ${db} with ${migrations_dir}"
    echo "migrated ${db} database with ${migrations_dir}"
  else
    echo "no ${migrations_dir} migrations to apply"
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

echo "created all databases"
