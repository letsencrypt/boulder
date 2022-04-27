{{ with secret "consul_int/issue/consul" "common_name=server.dev-general.consul" "ttl=24h" "alt_names=localhost" "ip_sans=127.0.0.1"}}
{{ .Data.certificate }}
{{ end }}
