#!/usr/bin/env bash

# Enable job mode.
set -m

function no_ctrlc() {
    echo
    prettyRed "Cleaning up and exiting..."
    rm -rf config/var/*.csr config/var/*.crt config/var/*.pem
    
    prettyRed "Stopping Vault..."
    killall vault
    
    prettyRed "Stopping Consul..."
    killall consul

    prettyRed "Stopping Nomad..."
    sudo killall nomad
    
    exit
}

function prettyRed() {
    tput setaf 1 && echo "==> $1" && tput sgr0
}

function pretty() {
    tput setaf 4 && echo "==> $1" && tput sgr0
}


pretty "Starting Vault Server"

command vault server -dev -config="config/vault.conf.hcl" &>/dev/null &
sleep 1
VAULT_TOKEN=$(cat ~/.vault-token)
VAULT_ADDR='http://127.0.0.1:8200'


pretty "Logging into Vault"

vault login -method=token "${VAULT_TOKEN}" &>/dev/null


pretty "Enabling PKI Secrets Engines"

#  Configure Boulder Root CA PKI Engine
vault secrets enable -path=boulder pki
vault secrets tune -max-lease-ttl=87600h boulder

# Configure Boulder Intermediate CA PKI Engine
vault secrets enable -path=boulder_int pki
vault secrets tune -max-lease-ttl=43800h boulder_int


pretty "Generating Root CAs"

# Boulder Root CA
vault write -field=certificate boulder/root/generate/internal \
    common_name="Boulder Root" ttl=87600h > config/var/ca_cert.crt


pretty "Generating the Intermediate CAs and CSRs"

# Boulder Intermediate CA
vault write -format=json boulder_int/intermediate/generate/internal \
    common_name="Boulder Intermediate Authority" \
    ttl="43800h" | jq -r '.data.csr' > config/var/boulder_int.csr


pretty "Signing Intermediate CA Certificates"

# Boulder Intermediate CA with Boulder Root CA
vault write -format=json boulder/root/sign-intermediate \
    csr=@config/var/boulder_int.csr format=pem_bundle \
    ttl="43800h" | jq -r '.data.certificate' > config/var/boulder_int.cert.pem


pretty "Deploying Intermediate CA Certificates to Vault"

# Boulder Intermediate CA
vault write boulder_int/intermediate/set-signed certificate=@config/var/boulder_int.cert.pem


pretty "Starting Consul Server"
command consul agent -dev -datacenter dev-general &>/dev/null &


pretty "Starting Nomad Server"
command sudo nomad agent -dev -dc dev-general \
 -log-level DEBUG -vault-enabled -vault-token="${VAULT_TOKEN}" -vault-address="${VAULT_ADDRESS}" -vault-create-from-role="root" &


vault write boulder_int/roles/boulder \
  allowed_domains="boulder" \
  allow_subdomains=true \
  generate_lease=true \
  max_ttl="720h"

pretty "Vault Root Token:"
echo "${VAULT_TOKEN}"


pretty "Waiting for ctrl+c to exit..."
trap no_ctrlc EXIT
while true
do
    sleep 10
done