datacenter             = "dev-general"
log_level              = "INFO"
verify_incoming        = false
verify_outgoing        = true
verify_server_hostname = true
ca_file                = "./config/var/consul-agent-ca.crt"
cert_file              = "./config/var/consul-agent.crt"
key_file               = "./config/var/consul-agent.key"
auto_encrypt {
  allow_tls = true
}

ports {
  dns      = 8600
  http     = -1
  https    = 8501
  grpc     = 8502
  serf_lan = 8301
  serf_wan = -1
  server   = 8300
}
