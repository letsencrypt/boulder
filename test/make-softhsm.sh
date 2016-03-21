#!/bin/bash
#
# Run this script to generate a SoftHSM config and import test-ca.key to use
# with Boulder. Note that we don't check in the generated config or database
# because they require absolute paths.
#
cd $(dirname $0)
export SOFTHSM_CONF=$PWD/sothsm.conf
echo 0:${PWD}/softhsm.db > ${SOFTHSM_CONF}
softhsm --init-token --slot 0 --label "softhsm token" --pin 1234 --so-pin 1234
softhsm --slot 0 --import test-ca.key  --label "happy hacker key" --pin 1234 --id FF
echo "Set SOFTHSM_CONF=${SOFTHSM_CONF} to use, and put in your Boulder config:"
cat << EOF
"Key": {
  "PKCS11": {
    "Module": "/usr/lib/softhsm/libsofthsm.so",
    "tokenLabel": "softhsm token",
    "privateKeyLabel": "happy hacker key",
    "pin": "1234"
  }
},
EOF
