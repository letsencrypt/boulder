# A JS tester for boulder

The node.js scripts in this directory provide a simple end-to-end test of Boulder.  (Using some pieces from [node-acme](https://github.com/letsencrypt/node-acme/))  To run:

# Run boulder in default test mode:

    cd ../../
    ./start.py

# To run cfssl with a Yubikey, edit test/boulder-pkcs11-example-config.json to
# add your PKCS#11 PIN (and module name, token name, and label). Then run:

    cd ../../
    BOULDER_CONFIG=test/boulder-pkcs11-example-config.json ./start.py

# Client side

    npm install
    node test.js
