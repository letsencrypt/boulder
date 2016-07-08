#!/bin/bash

set -e -u

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# start rsyslog
service rsyslog start

wait_tcp_port() {
    local host="$1" port="$2"

    # see http://tldp.org/LDP/abs/html/devref1.html for description of this syntax.
    while ! exec 6<>/dev/tcp/$host/$port; do
	echo "$(date) - still trying to connect to $host:$port"
	sleep 1
    done
    exec 6>&-
}

# make sure we can reach the mysqldb
wait_tcp_port boulder-mysql 3306

# make sure we can reach the rabbitmq
wait_tcp_port boulder-rabbitmq 5672

# create the database
MYSQL_CONTAINER=1 $DIR/create_db.sh

# Set up rabbitmq exchange
rabbitmq-setup -server amqp://boulder-rabbitmq

# Make sure SoftHSM container is up and using the correct key
wait_tcp_port boulder-hsm 5657
if [ ! -f test/test-ca.key.der ]; then
    openssl rsa -in test/test-ca.key -inform pem -out test/test-ca.key.der -outform der
fi
PKCS11_PROXY_SOCKET="tcp://boulder-hsm:5657" pkcs11-tool --module=/usr/local/lib/libpkcs11-proxy.so --write-object test/test-ca.key.der --type privkey --label key_label --pin 5678 --login --so-pin 1234

if [[ $# -eq 0 ]]; then
    exec ./start.py
fi

# TODO(jsha): Change to an unprivileged user before running commands. Currently,
# running as an unprivileged user causes the certbot integration test to fail
# during the test of the manual plugin. There's a call to killpg in there that
# kills the whole test, but only when run under `su buser -c "..."`
exec $@
