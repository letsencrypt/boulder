{{ with secret "consul_int/issue/consul" "common_name=server.dev-general.consul" "ttl=90d"}}
{{ .Data.issuing_ca }}
{{ end }}
