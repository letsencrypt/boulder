#!/bin/bash

set -e -u

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Start rsyslog. Note: Sometimes for unknown reasons /var/run/rsyslogd.pid is
# already present, which prevents the whole container from starting. We remove
# it just in case it's there.
rm -f /var/run/rsyslogd.pid
service rsyslog start

wait_tcp_port() {
    local host="$1" port="$2"

    # see http://tldp.org/LDP/abs/html/devref1.html for description of this syntax.
    while ! exec 6<>/dev/tcp/$host/$port; do
	echo "$(date) - still trying to connect to $host:$port"
	sleep 1
    done
    exec 6>&-
    echo "Connected to $host:$port!"
}
cat <<EOF >> /etc/hosts
127.0.0.1 sa.boulder ra.boulder wfe.boulder ca.boulder va.boulder publisher.boulder ocsp-updater.boulder admin-revoker.boulder
EOF

# make sure we can reach the mysqldb
wait_tcp_port boulder-mysql 3306

# create the database
MYSQL_CONTAINER=1 $DIR/create_db.sh

# Delaying loading private key into SoftHSM container until now so that switching
# out the signing key doesn't require rebuilding the boulder-tools image. Only
# convert key to DER once per container.
wait_tcp_port boulder-hsm 5657

addkey() {
  pkcs11-tool --module=/usr/local/lib/libpkcs11-proxy.so \
    --type privkey --pin 5678 --login --so-pin 1234 "$@";
}
addkey --token-label intermediate --write-object test/test-ca.key.der --label intermediate_key
addkey --token-label root --write-object test/test-root.key.der --label root_key

if [[ $# -eq 0 ]]; then
    exec ./start.py
fi

# TODO(jsha): Change to an unprivileged user before running commands. Currently,
# running as an unprivileged user causes the certbot integration test to fail
# during the test of the manual plugin. There's a call to killpg in there that
# kills the whole test, but only when run under `su buser -c "..."`
exec $@
