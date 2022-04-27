#!/usr/bin/env bash

# Enable job mode.
set -m

function no_ctrlc() {
    echo
    prettyRed "Cleaning up and exiting..."
    rm -rf config/var/* vault_audit.log
    
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
export VAULT_TOKEN=$(cat ~/.vault-token)
export VAULT_ADDR='http://127.0.0.1:8200'


pretty "Logging into Vault"

vault login -method=token "${VAULT_TOKEN}" &>/dev/null


pretty "Enabling Vault Audit Logging"
vault audit enable file file_path=vault_audit.log


pretty "Enabling PKI Secrets Engines"

#  Configure Boulder Root CA PKI Engine
vault secrets enable -path=boulder pki
vault secrets tune -max-lease-ttl=87600h boulder

# Configure Boulder Intermediate CA PKI Engine
vault secrets enable -path=boulder_int pki
vault secrets tune -max-lease-ttl=43800h boulder_int

#  Configure Consul Root CA PKI Engine
vault secrets enable -path=consul pki
vault secrets tune -max-lease-ttl=87600h consul

# Configure Consul Intermediate CA PKI Engine
vault secrets enable -path=consul_int pki
vault secrets tune -max-lease-ttl=43800h consul_int

pretty "Generating Root CAs"

# Boulder Root CA
vault write -field=certificate boulder/root/generate/internal \
    common_name="Boulder Root" ttl=87600h > config/var/boulder_ca_cert.crt

# Consul Root CA
vault write -field=certificate consul/root/generate/internal \
    common_name="Consul Root" ttl=87600h > config/var/consul_ca_cert.crt

# Configure Vault as Consul's CA/ set CA and CRL URLs.
vault write consul/config/urls \
    issuing_certificates="http://127.0.0.1:8200/v1/consul/ca" \
    crl_distribution_points="http://127.0.0.1:8200/v1/consul/crl"


pretty "Generating the Intermediate CAs and CSRs"

# Boulder Intermediate CA
vault write -format=json boulder_int/intermediate/generate/internal \
    common_name="Boulder Intermediate Authority" \
    ttl="43800h" | jq -r '.data.csr' > config/var/boulder_int.csr

# Consul Intermediate CA
vault write -format=json consul_int/intermediate/generate/internal \
    common_name="dev-general.consul" \
    ttl="43800h" | jq -r '.data.csr' > config/var/consul_int.csr


pretty "Signing Intermediate CA Certificates"

# Boulder Intermediate CA with Boulder Root CA
vault write -format=json boulder/root/sign-intermediate \
    csr=@config/var/boulder_int.csr format=pem_bundle \
    ttl="43800h" | jq -r '.data.certificate' > config/var/boulder_int.cert.pem

# Consul Intermediate CA with Consul Root CA
vault write -format=json consul/root/sign-intermediate \
    csr=@config/var/consul_int.csr format=pem_bundle \
    ttl="43800h" | jq -r '.data.certificate' > config/var/consul_int.cert.pem


pretty "Deploying Intermediate CA Certificates to Vault"

# Boulder Intermediate CA
vault write boulder_int/intermediate/set-signed certificate=@config/var/boulder_int.cert.pem

# Consul Intermediate CA
vault write consul_int/intermediate/set-signed certificate=@config/var/consul_int.cert.pem


pretty "Writing Vault Roles and Policies"

# Boulder PKI Role
# https://www.vaultproject.io/api-docs/secret/pki
vault write boulder_int/roles/boulder \
  allowed_domains="boulder" \
  allow_subdomains=true \
  require_cn=false \
  generate_lease=true

vault policy write boulder vault/int_boulder.policy.hcl

# Nomad Cluster Role
vault write /auth/token/roles/nomad-cluster \
  generate_lease=true \
  max_ttl="720h" \
  token_explicit_max_ttl=0 \
  name="nomad-cluster" \
  orphan=true \
  token_period=259200 \
  renewable=true

# Nomad Cluster Policy
vault policy write nomad-cluster vault/boulder.policy.hcl

# Consul PKI Role
vault write consul_int/roles/consul \
    allowed_domains="consul" \
    allow_subdomains=true \
    generate_lease=true \
    max_ttl="720h"


# pretty "Issue Server Certificates"

# Issue Consul Server Certificate
# vault write consul_int/issue/consul \
#   common_name="dev-general.consul" ttl="24h" | tee config/var/consul-certs.txt

# Issue Consul Server Certificate
# vault write consul_int/issue/consul \
#   common_name="server1.dev-general.consul" ttl="24h" | tee config/var/consul-server-certs.txt

# Nomad PKI Policy
# tee config/var/consul-tls-policy.hcl <<EOF
# path "nomad_int/issue/consul" {
#   capabilities = ["update"]
# }
# EOF

# vault policy write consul-tls-policy config/var/consul-tls-policy.hcl

# Generate Nomad TLS Token
# VAULT_NOMAD_TLS_TOKEN=$(vault token create -policy="tls-policy" -period=24h -orphan | grep 'token' | sed 's|token                ||')

pretty "Setup consul-template"
tee config/var/template-consul-tls-config.hcl <<EOF
# This denotes the start of the configuration section for Vault. All values
# contained in this section pertain to Vault.
vault {
  # This is the address of the Vault leader. The protocol (http(s)) portion
  # of the address is required.
  address      = "http://localhost:8200"

  # This value can also be specified via the environment variable VAULT_TOKEN.
  # token        = "root"

  unwrap_token = false

  renew_token  = false
}

# This block defines the configuration for a template. Unlike other blocks,
# this block may be specified multiple times to configure multiple templates.
template {
  # This is the source file on disk to use as the input template. This is often
  # called the "consul-template template".
  source      = "./config/template/consul-agent.crt.tpl"

  # This is the destination path on disk where the source template will render.
  # If the parent directories do not exist, consul-template will attempt to
  # create them, unless create_dest_dirs is false.
  destination = "./config/var/consul-agent.crt"

  # This is the permission to render the file. If this option is left
  # unspecified, consul-template will attempt to match the permissions of the
  # file that already exists at the destination path. If no file exists at that
  # path, the permissions are 0644.
  perms       = 0700

  # This is the optional command to run when the template is rendered. The
  # command will only run if the resulting template changes.
  # command     = "sh -c 'date && consul reload'"
}

template {
  source      = "./config/template/consul-agent.key.tpl"
  destination = "./config/var/consul-agent.key"
  perms       = 0700
  # command     = "sh -c 'date && consul reload'"
}

template {
  source      = "./config/template/consul-ca.crt.tpl"
  destination = "./config/var/consul-ca.crt"
  # command     = "sh -c 'date && consul reload'"
}
EOF

# pretty "Vault Root Token:"
# echo "${VAULT_NOMAD_TLS_TOKEN}"

command consul-template -config="./config/var/template-consul-tls-config.hcl" &>/dev/null &

pretty "Waiting 5 seconds for consul-template to provision Consul certificates..."
sleep 5

pretty "Starting Consul Server"
command consul agent -dev -config-format=hcl -config-file="./config/consul.conf.hcl" &>/dev/null &


pretty "Starting Nomad Server"
command sudo nomad agent -dev -dc dev-general \
  -vault-token="${VAULT_TOKEN}" -config="config/nomad.conf.hcl" &>/dev/null &


pretty "Vault Root Token:"
echo "${VAULT_TOKEN}"

pretty "Waiting for ctrl+c to exit..."
trap no_ctrlc EXIT
while true
do
    sleep 10
done
