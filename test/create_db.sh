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

  if [[ "$BOULDER_CONFIG_DIR" = "test/config-next" ]]; then
    nextDir="./sa/_db-next/"

    # Goose exits non-zero if there are no migrations to apply with the error
    # message:
    #   "2016/09/26 15:43:38 no valid version found"
    # so we only want to run goose with the nextDir if there is a migrations
    # directory present with at least one migration
    if [ $(find "$nextDir/migrations" -maxdepth 0 -type d -not -empty 2>/dev/null) ]; then
      goose -path=${nextDir} -env=$dbenv up || die "unable to migrate ${db} with ${nextDir}"
      echo "migrated ${db} database with ${nextDir}"
    else
      echo "no ${nextDir} migrations to apply"
    fi
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
  ) &
done
wait

echo "created all databases"
