#!/bin/bash
#
# Run this script after pulling changes that have migrations, to migrate your
# local DB.
#
set -o errexit
set -o xtrace
cd $(dirname $0)/..

source test/db-common.sh

for svc in $SERVICES; do
  for dbenv in $DBENVS; do
    db="boulder_${svc}_${dbenv}"

    goose -path=./$svc/_db/ -env=$dbenv up || die "unable to migrate ${db}"
    echo "migrated ${db} database"
  done
done
echo "migrated all databases"

