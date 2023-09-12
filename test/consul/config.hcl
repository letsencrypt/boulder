client_addr = "0.0.0.0"
bind_addr   = "10.55.55.10"
log_level   = "ERROR"
// When set, uses a subset of the agent's TLS configuration (key_file,
// cert_file, ca_file, ca_path, and server_name) to set up the client for HTTP
// or gRPC health checks. This allows services requiring 2-way TLS to be checked
// using the agent's credentials.
enable_agent_tls_for_checks = true
tls {
  defaults {
    ca_file         = "test/grpc-creds/minica.pem"
    ca_path         = "test/grpc-creds/minica-key.pem"
    cert_file       = "test/grpc-creds/consul.boulder/cert.pem"
    key_file        = "test/grpc-creds/consul.boulder/key.pem"
    verify_incoming = false
  }
}
ui_config {
  enabled = true
}
ports {
  dns      = 53
  grpc_tls = 8503
}

services {
  id      = "akamai-purger-a"
  name    = "akamai-purger"
  address = "10.77.77.77"
  port    = 9099
  tags    = ["tcp"] // Required for SRV RR support in gRPC DNS resolution.
}

services {
  id      = "akamai-purger-b"
  name    = "akamai-purger"
  address = "10.88.88.88"
  port    = 9099
  tags    = ["tcp"] // Required for SRV RR support in gRPC DNS resolution.
}

services {
  id      = "boulder-a"
  name    = "boulder"
  address = "10.77.77.77"
}

services {
  id      = "boulder-a"
  name    = "boulder"
  address = "10.88.88.88"
}

services {
  id      = "ca-a"
  name    = "ca"
  address = "10.77.77.77"
  port    = 9093
  tags    = ["tcp"] // Required for SRV RR support in gRPC DNS resolution.
}

services {
  id      = "ca-b"
  name    = "ca"
  address = "10.88.88.88"
  port    = 9093
  tags    = ["tcp"] // Required for SRV RR support in gRPC DNS resolution.
}

services {
  id      = "ca1"
  name    = "ca1"
  address = "10.77.77.77"
  port    = 9093
  tags    = ["tcp"] // Required for SRV RR support in gRPC DNS resolution.
}

services {
  id      = "ca2"
  name    = "ca2"
  address = "10.88.88.88"
  port    = 9093
  tags    = ["tcp"] // Required for SRV RR support in gRPC DNS resolution.
}

services {
  id      = "crl-storer-a"
  name    = "crl-storer"
  address = "10.77.77.77"
  port    = 9109
  tags    = ["tcp"] // Required for SRV RR support in gRPC DNS resolution.
}

services {
  id      = "crl-storer-b"
  name    = "crl-storer"
  address = "10.88.88.88"
  port    = 9109
  tags    = ["tcp"] // Required for SRV RR support in gRPC DNS resolution.
}

services {
  id      = "dns-a"
  name    = "dns"
  address = "10.77.77.77"
  port    = 8053
  tags    = ["udp"] // Required for SRV RR support in VA RVA.
}

services {
  id      = "dns-b"
  name    = "dns"
  address = "10.88.88.88"
  port    = 8054
  tags    = ["udp"] // Required for SRV RR support in VA RVA.
}

services {
  id      = "nonce-a"
  name    = "nonce"
  address = "10.77.77.77"
  port    = 9101
  tags    = ["tcp"] // Required for SRV RR support in gRPC DNS resolution.
}

services {
  id      = "nonce-b"
  name    = "nonce"
  address = "10.88.88.88"
  port    = 9101
  tags    = ["tcp"] // Required for SRV RR support in gRPC DNS resolution.
}

services {
  id      = "nonce1"
  name    = "nonce1"
  address = "10.77.77.77"
  port    = 9101
  tags    = ["tcp"] // Required for SRV RR support in gRPC DNS resolution.
}

services {
  id      = "nonce2"
  name    = "nonce2"
  address = "10.88.88.88"
  port    = 9101
  tags    = ["tcp"] // Required for SRV RR support in gRPC DNS resolution.
}

services {
  id      = "publisher-a"
  name    = "publisher"
  address = "10.77.77.77"
  port    = 9091
  tags    = ["tcp"] // Required for SRV RR support in gRPC DNS resolution.
}

services {
  id      = "publisher-b"
  name    = "publisher"
  address = "10.88.88.88"
  port    = 9091
  tags    = ["tcp"] // Required for SRV RR support in gRPC DNS resolution.
}

services {
  id      = "publisher1"
  name    = "publisher1"
  address = "10.77.77.77"
  port    = 9091
  tags    = ["tcp"] // Required for SRV RR support in gRPC DNS resolution.
}

services {
  id      = "publisher2"
  name    = "publisher2"
  address = "10.88.88.88"
  port    = 9091
  tags    = ["tcp"] // Required for SRV RR support in gRPC DNS resolution.
}

services {
  id      = "ra-a"
  name    = "ra"
  address = "10.77.77.77"
  port    = 9094
  tags    = ["tcp"] // Required for SRV RR support in gRPC DNS resolution.
}

services {
  id      = "ra-b"
  name    = "ra"
  address = "10.88.88.88"
  port    = 9094
  tags    = ["tcp"] // Required for SRV RR support in gRPC DNS resolution.
}

services {
  id      = "ra1"
  name    = "ra1"
  address = "10.77.77.77"
  port    = 9094
  tags    = ["tcp"] // Required for SRV RR support in gRPC DNS resolution.
}

services {
  id      = "ra2"
  name    = "ra2"
  address = "10.88.88.88"
  port    = 9094
  tags    = ["tcp"] // Required for SRV RR support in gRPC DNS resolution.
}

services {
  id      = "rva1-a"
  name    = "rva1"
  address = "10.77.77.77"
  port    = 9097
  tags    = ["tcp"] // Required for SRV RR support in gRPC DNS resolution.
}

services {
  id      = "rva1-b"
  name    = "rva1"
  address = "10.77.77.77"
  port    = 9098
  tags    = ["tcp"] // Required for SRV RR support in gRPC DNS resolution.
}

services {
  id      = "sa-a"
  name    = "sa"
  address = "10.77.77.77"
  port    = 9095
  tags    = ["tcp"] // Required for SRV RR support in gRPC DNS resolution.
  checks = [
    {
      id              = "sa-a-grpc"
      name            = "sa-a-grpc"
      grpc            = "10.77.77.77:9095"
      grpc_use_tls    = true
      tls_server_name = "sa.boulder"
      tls_skip_verify = false
      interval        = "2s"
    },
    {
      id              = "sa-a-grpc-sa"
      name            = "sa-a-grpc-sa"
      grpc            = "10.77.77.77:9095/sa.StorageAuthority"
      grpc_use_tls    = true
      tls_server_name = "sa.boulder"
      tls_skip_verify = false
      interval        = "2s"
    },
    {
      id              = "sa-a-grpc-saro"
      name            = "sa-a-grpc-saro"
      grpc            = "10.77.77.77:9095/sa.StorageAuthorityReadOnly"
      grpc_use_tls    = true
      tls_server_name = "sa.boulder"
      tls_skip_verify = false
      interval        = "2s"
    }
  ]
}

services {
  id      = "sa-b"
  name    = "sa"
  address = "10.88.88.88"
  port    = 9095
  tags    = ["tcp"] // Required for SRV RR support in gRPC DNS resolution.
  checks = [
    {
      id              = "sa-b-grpc"
      name            = "sa-b-grpc"
      grpc            = "10.88.88.88:9095"
      grpc_use_tls    = true
      tls_server_name = "sa.boulder"
      tls_skip_verify = false
      interval        = "2s"
    },
    {
      id              = "sa-b-grpc-sa"
      name            = "sa-b-grpc-sa"
      grpc            = "10.88.88.88:9095/sa.StorageAuthority"
      grpc_use_tls    = true
      tls_server_name = "sa.boulder"
      tls_skip_verify = false
      interval        = "2s"
    },
    {
      id              = "sa-b-grpc-saro"
      name            = "sa-b-grpc-saro"
      grpc            = "10.88.88.88:9095/sa.StorageAuthorityReadOnly"
      grpc_use_tls    = true
      tls_server_name = "sa.boulder"
      tls_skip_verify = false
      interval        = "2s"
    }
  ]
}

services {
  id      = "sa1"
  name    = "sa1"
  address = "10.77.77.77"
  port    = 9095
  tags    = ["tcp"] // Required for SRV RR support in gRPC DNS resolution.
}

services {
  id      = "sa2"
  name    = "sa2"
  address = "10.88.88.88"
  port    = 9095
  tags    = ["tcp"] // Required for SRV RR support in gRPC DNS resolution.
}

services {
  id      = "va-a"
  name    = "va"
  address = "10.77.77.77"
  port    = 9092
  tags    = ["tcp"] // Required for SRV RR support in gRPC DNS resolution.
}

services {
  id      = "va-b"
  name    = "va"
  address = "10.88.88.88"
  port    = 9092
  tags    = ["tcp"] // Required for SRV RR support in gRPC DNS resolution.
}

services {
  id      = "va1"
  name    = "va1"
  address = "10.77.77.77"
  port    = 9092
  tags    = ["tcp"] // Required for SRV RR support in gRPC DNS resolution.
}

services {
  id      = "va2"
  name    = "va2"
  address = "10.88.88.88"
  port    = 9092
  tags    = ["tcp"] // Required for SRV RR support in gRPC DNS resolution.
}

services {
  id      = "bredis3"
  name    = "redisratelimits"
  address = "10.33.33.4"
  port    = 4218
  tags    = ["tcp"] // Required for SRV RR support in DNS resolution.
}

services {
  id      = "bredis4"
  name    = "redisratelimits"
  address = "10.33.33.5"
  port    = 4218
  tags    = ["tcp"] // Required for SRV RR support in DNS resolution.
}

//
// The following services are used for testing the gRPC DNS resolver.
//

// CaseOne config will have 2 SRV records. The first will have 0 backends, the
// second will have 1.
services {
  id      = "case1a"
  name    = "case1a"
  address = "10.77.77.77"
  port    = 9101
  tags    = ["tcp"] // Required for SRV RR support in gRPC DNS resolution.
  checks = [
    {
      id       = "case1a-failing"
      name     = "case1a-failing"
      http     = "http://localhost:12345" // invalid url
      method   = "GET"
      interval = "2s"
    }
  ]
}

services {
  id      = "case1b"
  name    = "case1b"
  address = "10.88.88.88"
  port    = 9101
  tags    = ["tcp"] // Required for SRV RR support in gRPC DNS resolution.
}

// CaseTwo config will have 2 SRV records. The first will not be configured in
// Consul, the second will have 1 backend.
services {
  id      = "case2b"
  name    = "case2b"
  address = "10.88.88.88"
  port    = 9101
  tags    = ["tcp"] // Required for SRV RR support in gRPC DNS resolution.
}

// CaseThree config will have 2 SRV records. Neither will be configured in
// Consul.


// CaseFour config will have 2 SRV records. Neither will have backends.
services {
  id      = "case4a"
  name    = "case4a"
  tags    = ["tcp"] // Required for SRV RR support in gRPC DNS resolution.
  address = "10.77.77.77"
  port    = 9101
  tags    = ["tcp"] // Required for SRV RR support in gRPC DNS resolution.
  checks = [
    {
      id       = "case4a-failing"
      name     = "case4a-failing"
      http     = "http://localhost:12345" // invalid url
      method   = "GET"
      interval = "2s"
    }
  ]
}

services {
  id      = "case4b"
  name    = "case4b"
  address = "10.88.88.88"
  port    = 9101
  tags    = ["tcp"] // Required for SRV RR support in gRPC DNS resolution.
  checks = [
    {
      id       = "case4b-failing"
      name     = "case4b-failing"
      http     = "http://localhost:12345" // invalid url
      method   = "GET"
      interval = "2s"
    }
  ]
}
