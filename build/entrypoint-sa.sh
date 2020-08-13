#!/bin/bash

set -e -u

# create the database
MYSQL_CONTAINER=1 test/create_db.sh

exec ./entrypoint-k8s.sh $@
