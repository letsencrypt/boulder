# A JS tester for boulder

The node.js scripts in this directory provide a simple end-to-end test of Boulder.  (Using some pieces from [node-acme](https://github.com/letsencrypt/node-acme/))  To run:

```
# Install dependencies
> npm install inquirer cli node-forge

# Start cfssl with signing parameters
# (These are the default parameters to use a Yubikey.)
# (You'll need to make your own key, cert, and policy.)
> go install -tags pkcs11 github.com/cloudflare/cfssl/cmd/cfssl
> cfssl serve -port 8888 -ca ca.cert.pem \
              -pkcs11-module "/Library/OpenSC/lib/opensc-pkcs11.so" \
              -pkcs11-token "Yubico Yubik NEO CCID" \
              -pkcs11-pin 123456 \
              -pkcs11-label "PIV AUTH key" \
              -config policy.json

# Start boulder
# (Change CFSSL parameters to match your setup.)
> go install github.com/letsencrypt/boulder
> boulder-start --cfssl localhost:8888
                --cfsslProfile ee \
                --cfsslAuthKey 79999d86250c367a2b517a1ae7d409c1 \
                monolithic

# Client side
> mkdir -p .well-known/acme-challenge/
> node demo.js
> mv -- *.txt .well-known/acme-challenge/ # In a different window
> python -m SimpleHTTPServer 5001         # In yet another window
```
