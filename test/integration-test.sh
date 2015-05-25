#!/bin/bash
cd $(dirname $0)/..

# Ensure cleanup
trap "trap '' SIGTERM && kill -- -$$" SIGINT SIGTERM EXIT

go run ./cmd/boulder/main.go --config test/boulder-test-config.json &>/dev/null &
go run Godeps/_workspace/src/github.com/cloudflare/cfssl/cmd/cfssl/cfssl.go \
  -loglevel 0 \
  serve \
  -port 9300 \
  -ca test/test-ca.pem \
  -ca-key test/test-ca.key \
  -config test/cfssl-config.json &>/dev/null &

cd test/js
npm install

# Wait for Boulder to come up
until nc localhost 4300 < /dev/null ; do sleep 1 ; done

CERT_KEY=$(mktemp /tmp/cert_XXXXX.pem)
CERT=$(mktemp /tmp/cert_XXXXX.crt)

node test.js --email foo@bar.com --agree true \
  --domain foo.com --new-reg http://localhost:4300/acme/new-reg \
  --certKey ${CERT_KEY} --cert ${CERT} && \
node revoke.js ${CERT} ${CERT_KEY} http://localhost:4300/acme/revoke-cert/

STATUS=$?

# Cleanup
rm -f ${CERT_KEY}
rm -f ${CERT}
rm -f account-key.pem
rm -f temp-cert.pem

exit $STATUS
