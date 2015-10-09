#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# start rsyslog
service rsyslog start &&

# wait until the mysql instance has started fully
# this is awful
sleep 5

# create the database
source $DIR/create_db.sh

$@
