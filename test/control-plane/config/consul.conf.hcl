datacenter             = "dev-general"
log_level              = "ERROR"
verify_incoming        = false
verify_outgoing        = true
verify_server_hostname = true
ca_file                = "tls/consul/consul-agent-ca.pem"
cert_file              = "tls/consul/dev-general-server-consul-0.pem"
key_file               = "tls/consul/dev-general-server-consul-0-key.pem"

ports {
  dns      = 8600
  http     = -1
  https    = 8501
  grpc     = 8502
  serf_lan = 8301
  serf_wan = -1
  server   = 8300
}
