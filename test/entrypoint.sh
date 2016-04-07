#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# start rsyslog
service rsyslog start &&

# make sure we can reach the mysqldb
# see http://tldp.org/LDP/abs/html/devref1.html for description of this syntax.
while ! exec 6<>/dev/tcp/boulder-mysql/3306; do
    echo "$(date) - still trying to connect to mysql at boulder-mysql:3306"
    sleep 1 || exit
done

# make sure we can reach the rabbitmq
while ! exec 6<>/dev/tcp/boulder-rabbitmq/5672; do
    echo "$(date) - still trying to connect to rabbitmq at boulder-rabbitmq:5672"
    sleep 1 || exit
done

exec 6>&-
exec 6<&-

# create the database
$DIR/create_db.sh

# Set up rabbitmq exchange
go run cmd/rabbitmq-setup/main.go -server amqp://boulder-rabbitmq

$@
