#!/bin/bash -ex
cd $(dirname $0)
TEST=../../../test/
single-ocsp -issuer $TEST/test-root.der \
        -responder $TEST/test-root.der \
        -target $TEST/test-ca2.der \
        -template template-good.json \
        -pkcs11 $TEST/test-ca.key-pkcs11.json \
        -out ocsp-good.b64der

single-ocsp -issuer $TEST/test-root.der \
        -responder $TEST/test-root.der \
        -target $TEST/test-ca2.der \
        -template template-good-2014.json \
        -pkcs11 $TEST/test-ca.key-pkcs11.json \
        -out ocsp-good-2014.b64der

cat ocsp-good-2014.b64der ocsp-good.b64der > $TEST/issuer-ocsp-responses.txt
