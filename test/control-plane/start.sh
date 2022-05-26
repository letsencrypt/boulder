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

    prettyRed "Stopping Consul-Template..."
    killall consul-template -9

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
    allowed_domains="dev-general.consul" \
    allow_subdomains=true \
    generate_lease=true \
    max_ttl="720h"

pretty "Setup consul-template"

tee config/var/template-consul-tls-config.hcl <<EOF
vault {
  address      = "http://localhost:8200"
  unwrap_token = false
  renew_token  = true
}

template {
  source      = "./config/template/consul-agent.crt.tpl"
  destination = "./config/var/consul-agent.crt"
  perms       = 0700
  #command     = "sudo pkill -HUP consul nomad"
}

template {
  source      = "./config/template/consul-agent.key.tpl"
  destination = "./config/var/consul-agent.key"
  perms       = 0700
  #command     = "sudo pkill -HUP consul nomad"
}

template {
  source      = "./config/template/consul-ca.crt.tpl"
  destination = "./config/var/consul-agent-ca.crt"
  perms       = 0700
  #command     = "sudo pkill -HUP consul nomad"
}
EOF

# Consul PKI Policy
tee consul-tls-policy.hcl <<EOF
path "consul_int/issue/consul" {
  capabilities = ["read", "create", "update", "delete"]
}
EOF

# Consul PKI Role
vault write consul_int/roles/consul \
    allowed_domains="dev-general.consul" \
    allow_subdomains=true \
    generate_lease=true \
    max_ttl="720h"

vault policy write consul-tls consul-tls-policy.hcl

CONSUL_TLS_TOKEN=$(vault token create -policy="consul-tls" -period=24h -orphan -format="json" | jq -r .auth.client_token)

pretty "Consul TLS Token:"
echo "${CONSUL_TLS_TOKEN}"

pretty "Templating Consul TLS Certs"

consul-template -vault-token="${CONSUL_TLS_TOKEN}" -config="./config/var/template-consul-tls-config.hcl" -once

pretty "Starting Consul Server"
command consul agent -dev -config-format=hcl -config-file="./config/consul.conf.hcl" &>/dev/null &

pretty "Wait for Consul to Start"
while true
do
  resp=$(curl -k -sw '%{http_code}' https://localhost:8501/v1/agent/checks | tail -1 | xargs)
  if [ "$resp" = "200" ]
  then
    echo "Consul agent is running."
    break
  else
    echo "Waiting for Consul agent to start..."
    sleep 1
  fi
done

pretty "Enabling Consul ACLs"
export CONSUL_HTTP_SSL=true
export CONSUL_HTTP_ADDR=https://127.0.0.1:8501
export CONSUL_HTTP_SSL_VERIFY=false
CONSUL_TOKEN=$(consul acl bootstrap -format=json | jq -r '.SecretID')

pretty "Starting Nomad Server"
command sudo nomad agent -dev -dc dev-general \
  -vault-token="${VAULT_TOKEN}" -consul-token="${CONSUL_TOKEN}" -config="config/nomad.conf.hcl" &>/dev/null &

pretty "Wait for Nomad to Start"
while true
do
  # Nomad will return a 403 on all endpoints once it's ready to have ACLs
  # bootstrapped.
  resp=$(curl -k -sw '%{http_code}' http://127.0.0.1:4646/v1/agent/members | grep -o 403)
  if [ "$resp" = "403" ]
  then
    echo "Nomad agent is running."
    break
  else
    echo "Waiting for Nomad agent to start..."
    sleep 1
  fi
done

pretty "Bootstrapping Nomad ACLs"
export NOMAD_TOKEN=$(nomad acl bootstrap -json | jq -r ".SecretID")

# https://learn.hashicorp.com/tutorials/nomad/access-control-policies
tee config/var/nomad_sre_policy.hcl <<EOF
namespace "*" {
  // Disallow access to execute shell commands from the web UI.
  deny   = ["alloc-exec", "alloc-node-exec"]
  policy = "write"
}
node {
  policy = "write"
}
agent {
  policy = "write"
}
host_volume "*" {
  policy = "write"
}
plugin {
  policy = "read"
}
EOF

tee config/var/nomad_ro_policy.hcl <<EOF
namespace "*" {
  policy = "read"
}
node {
  policy = "read"
}
agent {
  policy = "read"
}
plugin {
  policy = "read"
}
EOF

pretty "Applying Nomad ACL Policies"
# https://www.nomadproject.io/docs/commands/acl/policy-apply
nomad acl policy apply sre "./config/var/nomad_sre_policy.hcl"
nomad acl policy apply ro "./config/var/nomad_ro_policy.hcl"

pretty "Starting Consul-Template: Consul TLS"
sed -i '' 's|#command|command|g' ./config/var/template-consul-tls-config.hcl
command consul-template -vault-token="${CONSUL_TLS_TOKEN}" -config="./config/var/template-consul-tls-config.hcl" &>/dev/null &

pretty "Vault Root Token (run once before using vault CLI commands):"
echo "export VAULT_TOKEN=\"${VAULT_TOKEN}\""
echo
pretty "Consul Management Token (run once before using consul CLI commands):"
echo "export CONSUL_TOKEN=\"${CONSUL_TOKEN}\""
echo
pretty "Nomad Management Token (run once before using nomad CLI commands):"
echo "export NOMAD_TOKEN=\"${NOMAD_TOKEN}\""
echo
pretty "To issue an 'sre' Nomad ACL token, run:"
echo "nomad acl token create -type=\"client\" -policy=\"sre\""
echo
pretty "To issue a 'read-only' Nomad ACL token, run:"
echo "nomad acl token create -type=\"client\" -policy=\"ro\""
echo
pretty "Waiting for ctrl+c to exit..."
trap no_ctrlc EXIT
while true
do
    sleep 10
done
