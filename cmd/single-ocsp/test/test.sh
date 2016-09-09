#!/bin/bash -ex
cd $(dirname $0)
TEST=../../../test/
go build ../
./single-ocsp -issuer $TEST/test-root.pem \
        -target $TEST/test-ca2.pem \
        -template template-good.json \
        -pkcs11 $TEST/test-ca.key-pkcs11.json \
        -out ocsp-good.b64der

./single-ocsp -issuer $TEST/test-root.pem \
        -target $TEST/test-ca2.pem \
        -template template-good-2014.json \
        -pkcs11 $TEST/test-ca.key-pkcs11.json \
        -out ocsp-good-2014.b64der

cat ocsp-good-2014.b64der ocsp-good.b64der > $TEST/issuer-ocsp-responses.txt
