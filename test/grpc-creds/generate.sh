#!/bin/bash
set -e
set -o xtrace

validity="3650"
size="2048"
key_path="key.pem"
ca_path="ca.pem"
duocsr_path="duo.csr"
server_path="server.pem"
client_path="client.pem"

# generate key
openssl genrsa -out $key_path $size
# generate ca
openssl req -x509 -new -nodes -key $key_path -sha256 -days $validity -subj "/O=boulder/CN=grpc-test-ca" -out $ca_path
# generate csr for server + client (TODO(#1719): generate individual certs for each service name)
openssl req -new -key $key_path -out $duocsr_path -subj "/O=boulder/CN=boulder"
# generate server cert
openssl x509 -req -in $duocsr_path -CA $ca_path -CAkey $key_path -CAcreateserial -days $validity -sha256 -out $server_path
# generate client cert
openssl x509 -req -in $duocsr_path -CA $ca_path -CAkey $key_path -CAcreateserial -days $validity -sha256 -out $client_path

rm $duocsr_path
