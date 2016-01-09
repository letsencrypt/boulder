#!/bin/bash
set -o errexit
cd $(dirname $0)/..
source test/db-common.sh


# set db connection for if running in a seperate container or not
dbconn="-u root"
if [[ ! -z "$MYSQL_CONTAINER" ]]; then
	dbconn="-u root -h 127.0.0.1 --port 3306"
fi


DB_VERSION=$(  mysql $dbconn -e "status;" | grep "Server version" | sed -e 's/-Maria.*//
s/\.[0-9][0-9]*$//
s/Server version://
s/^.*-//
s/ //g
s/	//g
' )

# echo "DB_VERSION=$DB_VERSION"

# vesion contains 10.0 or 10.1 or 10.?
DB_MAJOR=$( echo $DB_VERSION | cut -d '.' -f 1 )
DB_MINOR=$( echo $DB_VERSION | cut -d '.' -f 2 )

if (( "$DB_MAJOR" < 10 )) ; then
	echo "FAILED: Databse version 10 or newer is supported.  Found $DB_VERSION"
	exit 1
fi
if [ -f test/create_db_users_$DB_VERSION.sql ] ; then
	mysql $dbconn < test/create_db_users_$DB_VERSION.sql
elif [ -f test/create_db_users.sql ] ; then
	mysql $dbconn < test/create_db_users.sql
fi

# Drop all users to get a fresh start
mysql $dbconn < test/drop_users.sql

if [ -f test/create_db_users_$DB_VERSION.sql ] ; then
	mysql $dbconn < test/create_db_users_$DB_VERSION.sql
elif [ -f test/create_db_users.sql ] ; then
	mysql $dbconn < test/create_db_users.sql
fi

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
			mysql $dbconn -D $db < $USERS_SQL || die "PJS1 unable to add users to ${db}"
			echo "added users to ${db}"
		fi
		) &
	done
done
wait

echo "created all databases"
