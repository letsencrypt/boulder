#!/bin/bash
set -o errexit -o pipefail
cd $(dirname $0)/..
source test/db-common.sh

# set db connection for if running in a separate container or not
dbconn="-u root"
if [[ $MYSQL_CONTAINER ]]; then
	dbconn="-u root -h 127.0.0.1 --port 3306"
fi

# We grant permissions to users connecting using both localhost and
# its explicit IPv4 and IPv6 addresses for maximum compatibilities
# with MySQL setups.
mysql_host_list="localhost 127.0.0.1 ::1"

# Print SQL to drop the user in $1.
# Note that dropping a non-existing user produces an error that aborts the
# script, so we first grant a harmless privilege to each user to ensure it
# exists.
print_drop_user() {
	local user="$1" host
	for host in $mysql_host_list; do
		echo "GRANT USAGE ON *.* TO '$user'@'$host';"
		echo "DROP USER '$user'@'$host';"
	done
}

# Print SQL to grant permission in $1 on the table $2 to the user $3.
print_grant() {
	local privileges="$1" table="$2" user="$3"
	for host in $mysql_host_list; do
		echo "GRANT $privileges ON $table TO '$user'@'$host';"
	done
}

# MariaDB sets the default binlog_format to STATEMENT,
# which causes warnings that fail tests. Instead set it
# to the format we use in production, MIXED.
mysql $dbconn -e "SET GLOBAL binlog_format = 'MIXED';"

# Drop all users to get a fresh start
. test/drop_users.sh | mysql $dbconn

for svc in $SERVICES; do
	for dbenv in $DBENVS; do
		(
		db="boulder_${svc}_${dbenv}"
		create_script="drop database if exists \`${db}\`; create database if not exists \`${db}\`;"

		mysql $dbconn -e "$create_script" || die "unable to create ${db}"

		echo "created empty ${db} database"

		goose -path=./$svc/_db/ -env=$dbenv up || die "unable to migrate ${db}"
		echo "migrated ${db} database"

		USERS_SQL=test/${svc}_db_users.sh
		if [[ -f $USERS_SQL ]]; then
			. "$USERS_SQL" | mysql $dbconn -D $db || \
				die "unable to add users to ${db}"
			echo "added users to ${db}"
		fi
		) &
	done
done
wait

echo "created all databases"
