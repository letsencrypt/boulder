#!/bin/bash

# Awaits for the required TCP socket to be available
wait_tcp_socket() {
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

# Start the daemon in the background
PKCS11_DAEMON_SOCKET=tcp://0.0.0.0:${PKCS11_DAEMON_PORT} /usr/local/bin/pkcs11-daemon /usr/lib/softhsm/libsofthsm2.so &

# Make sure we can reach the pkcs11 daemon's TCP socket
wait_tcp_socket localhost ${PKCS11_DAEMON_PORT}

# Import keys
softhsm2-util --pin 5678 --so-pin 1234 --id 333333 --token intermediate \
--import /srv/secret/test-ca.key --label intermediate_key
softhsm2-util --pin 5678 --so-pin 1234 --id 777777 --token root \
--import /srv/secret/test-root.key --label root_key

# Prepare container logging
./entrypoint-k8s.sh

# Wait for the pkcs11 daemon to finish
wait $(pidof pkcs11-daemon)
