

vault {
  enabled          = true
  address          = "http://127.0.0.1:8200"
  create_from_role = "nomad-cluster"
}

consul {
  address   = "localhost:8501"
  ssl       = true
  ca_file   = "./config/var/consul-agent-ca.crt"
  cert_file = "./config/var/consul-agent.crt"
  key_file  = "./config/var/consul-agent.key"
}

acl {
  enabled = true
}
