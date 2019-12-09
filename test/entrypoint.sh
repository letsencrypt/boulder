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
    local max_tries="120"
    for n in `seq 1 $max_tries` ; do
      if exec 6<>/dev/tcp/$host/$port; then
        break
      else
        echo "$(date) - still trying to connect to $host:$port"
        sleep 1
      fi
      if [ "$n" -eq "$max_tries" ]; then
        echo "unable to connect"
        exit 1
      fi
    done
    exec 6>&-
    echo "Connected to $host:$port"
}
# make sure we can reach the mysqldb
wait_tcp_port boulder-mysql 3306

# create the database
MYSQL_CONTAINER=1 $DIR/create_db.sh

if [ -n "${PKCS11_PROXY_SOCKET:-}" ]; then
  # Delaying loading private key into SoftHSM container until now so that switching
  # out the signing key doesn't require rebuilding the boulder-tools image. Only
  # convert key to DER once per container.
  wait_tcp_port boulder-hsm 5657

  addobj() {
    pkcs11-tool --module=/usr/local/lib/libpkcs11-proxy.so \
      --pin 5678 --login --so-pin 1234 "$@";
  }
  addobj --id 333333 --token-label intermediate --type privkey --write-object test/test-ca.key.der --label intermediate_key
  addobj --id 777777 --token-label root         --type privkey --write-object test/test-root.key.der --label root_key
  addobj --id 333333 --token-label intermediate --type pubkey  --write-object test/test-ca.pubkey.der --label intermediate_key
  addobj --id 777777 --token-label root         --type pubkey  --write-object test/test-root.pubkey.der --label root_key
fi

if [[ $# -eq 0 ]]; then
    # the activate script touches PS1, which is undefined, so we have to relax
    # the "fail on undefined" setting here.
    set +u
    source ${CERTBOT_PATH:-/certbot}/${VENV_NAME:-venv3}/bin/activate
    exec python3 ./start.py
fi

exec $@
