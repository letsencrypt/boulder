#!/bin/bash
set -o errexit
cd $(dirname $0)/..
source test/db-common.sh

# set db connection for if running in a separate container or not
dbconn="-u root"
if [[ $MYSQL_CONTAINER ]]; then
	dbconn="-u root -h boulder-mysql --port 3306"
fi

APPLY_NEXT_MIGRATIONS=${APPLY_NEXT_MIGRATIONS:-true}

# MariaDB sets the default binlog_format to STATEMENT,
# which causes warnings that fail tests. Instead set it
# to the format we use in production, MIXED.
mysql $dbconn -e "SET GLOBAL binlog_format = 'MIXED';"

for dbenv in $DBENVS; do
  (
  db="boulder_sa_${dbenv}"

  if mysql $dbconn -e 'show databases;' | grep $db > /dev/null; then
    echo "Database $db already exists - skipping create"
  else
    create_script="drop database if exists \`${db}\`; create database if not exists \`${db}\`;"

    mysql $dbconn -e "$create_script" || die "unable to create ${db}"

    echo "created empty ${db} database"
  fi

  goose -path=./sa/_db/ -env=$dbenv up || die "unable to migrate ${db} with ./sa/_db/"
  echo "migrated ${db} database with ./sa/_db/"

  if [[ "$APPLY_NEXT_MIGRATIONS" = true ]]; then
    goose -path=./sa/_db-next/ -env=$dbenv up || die "unable to migrate ${db} with ./sa/_db-next/"
    echo "migrated ${db} database with ./sa/_db-next/"
  fi

  # With MYSQL_CONTAINER, patch the GRANT statements to
  # use 127.0.0.1, not localhost, as MySQL may interpret
  # 'username'@'localhost' to mean only users for UNIX
  # socket connections.
  USERS_SQL=test/sa_db_users.sql
  if [[ ${MYSQL_CONTAINER} ]]; then
    sed -e "s/'localhost'/'%'/g" < ${USERS_SQL} | \
      mysql $dbconn -D $db || die "unable to add users to ${db}"
  else
    sed -e "s/'localhost'/'127.%'/g" < $USERS_SQL | \
      mysql $dbconn -D $db < $USERS_SQL || die "unable to add users to ${db}"
  fi
  echo "added users to ${db}"
  ) &
done
wait

echo "created all databases"
