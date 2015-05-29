# A JS tester for boulder

The node.js scripts in this directory provide a simple end-to-end test of Boulder.  (Using some pieces from [node-acme](https://github.com/letsencrypt/node-acme/))  To run:

# Install dependencies (run in this directory).

    npm install

# Run boulder in default test mode (no Yubikey, start cfssl automatically):

    cd ../
    ./start.sh

# To run cfssl with a Yubikey:
# (You'll need to make your own key, cert, and policy.)

    go install -tags pkcs11 github.com/cloudflare/cfssl/cmd/cfssl
    cfssl serve -port 9000 -ca ca.cert.pem \
                  -pkcs11-module "/Library/OpenSC/lib/opensc-pkcs11.so" \
                  -pkcs11-token "Yubico Yubik NEO CCID" \
                  -pkcs11-pin 123456 \
                  -pkcs11-label "PIV AUTH key" \
                  -config policy.json

# Client side

    node test.js
