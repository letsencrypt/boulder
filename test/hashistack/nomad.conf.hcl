datacenter = "dev-general"
log_level  = "ERROR"

consul {
  address   = "localhost:8501"
  ssl       = true
  ca_file   = "tls/consul/consul-agent-ca.pem"
  cert_file = "tls/attache/consul/dev-general-client-consul-0.pem"
  key_file  = "tls/attache/consul/dev-general-client-consul-0-key.pem"
}

# Enable CORS, retrieving logs is done via IP so we need CORS
http_api_response_headers {
  Access-Control-Allow-Origin = "*"
}
