# A JS tester for boulder

The node.js scripts in this directory provide a simple end-to-end test of Boulder.  (Using some pieces from [node-acme](https://github.com/letsencrypt/node-acme/))  To run:

# Install dependencies

    npm install

# Make a test key and cert.

    openssl req -newkey rsa:2048 -x509 -days 3650 \
      -subj /CN='happy hacker fake CA' -nodes -out ca.pem -keyout ca.key

# Start cfssl with signing parameters
# For use without a Yubikey:

    cfssl serve -port 9000 -ca=ca.pem -ca-key=ca.key

# With a Yubikey:
# (You'll need to make your own key, cert, and policy.)

    go install -tags pkcs11 github.com/cloudflare/cfssl/cmd/cfssl
    cfssl serve -port 9000 -ca ca.cert.pem \
                  -pkcs11-module "/Library/OpenSC/lib/opensc-pkcs11.so" \
                  -pkcs11-token "Yubico Yubik NEO CCID" \
                  -pkcs11-pin 123456 \
                  -pkcs11-label "PIV AUTH key" \
                  -config policy.json

# Start boulder
# (Change CFSSL parameters to match your setup.)

    go install github.com/letsencrypt/boulder/cmd/boulder
    boulder --config test/example-config.json

# Client side

    mkdir -p .well-known/acme-challenge/
    node test.js
    mv -- *.txt .well-known/acme-challenge/ # In a different window
    python -m SimpleHTTPServer 5001         # In yet another window
