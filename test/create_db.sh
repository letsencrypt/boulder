#!/bin/bash
set -o errexit
cd $(dirname $0)/..
source test/db-common.sh

# set db connection for if running in a separate container or not
dbconn="-u root"
if [[ ! -z "$MYSQL_CONTAINER" ]]; then
	dbconn="-u root -h 127.0.0.1 --port 3306"
fi

# Drop all users to get a fresh start
mysql $dbconn < test/drop_users.sql

for svc in $SERVICES; do
	for dbenv in $DBENVS; do
		(
		db="boulder_${svc}_${dbenv}"
		create_script="drop database if exists \`${db}\`; create database if not exists \`${db}\`;"

		mysql $dbconn -e "$create_script" || die "unable to create ${db}"

		echo "created empty ${db} database"

		goose -path=./$svc/_db/ -env=$dbenv up || die "unable to migrate ${db}"
		echo "migrated ${db} database"

		USERS_SQL=test/${svc}_db_users.sql
		if [[ -f "$USERS_SQL" ]]; then
			mysql $dbconn -D $db < $USERS_SQL || die "unable to add users to ${db}"
			echo "added users to ${db}"
		fi
		) &
	done
done
wait

echo "created all databases"
