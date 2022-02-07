repo-dir = "/Users/samantha/repos/boulder"

await-dependency-sh-template = <<-EOF
  #!/usr/bin/env bash
  echo -n 'waiting for service'
  until nslookup -port=8600 {{ env "DEPENDENCY_NAME" }}.service.consul 0.0.0.0 2>&1 >/dev/null
  do echo '.'
      sleep 2
  done
EOF

va-remote-json-template = <<-EOF
  {
    "va": {
      "userAgent": "boulder-remote-a",
      "debugAddr": ":{{ env "NOMAD_PORT_debug" }}",
      "portConfig": {
        "httpPort": {{ env "NOMAD_PORT_http" }},
        "httpsPort": {{ env "NOMAD_PORT_https" }},
        "tlsPort": {{ env "NOMAD_PORT_https" }}
      },
      "dnsTries": 3,
      "dnsResolvers": [
        "127.0.0.1:8053",
        "127.0.0.1:8054"
      ],
      "issuerDomain": "happy-hacker-ca.invalid",
      "tls": {
        "caCertfile": "{{ env "REPO_DIR" }}/test/grpc-creds/minica.pem",
        "certFile": "{{ env "REPO_DIR" }}/test/grpc-creds/va.boulder/cert.pem",
        "keyFile": "{{ env "REPO_DIR" }}/test/grpc-creds/va.boulder/key.pem"
      },
      "grpc": {
        "address": ":{{ env "NOMAD_PORT_grpc" }}",
        "clientNames": [
          "health-checker.boulder",
          "va.boulder"
        ]
      },
      "features": {
        "CAAValidationMethods": true,
        "CAAAccountURI": true
      },
      "accountURIPrefixes": [
        "http://boulder:4000/acme/reg/",
        "http://boulder:4001/acme/acct/"
      ]
    },

    "syslog": {
      "stdoutlevel": 6,
      "sysloglevel": 4
    },
    "beeline": {
        "mute": true,
        "dataset": "Test"
    },

    "common": {
      "dnsTimeout": "1s",
      "dnsAllowLoopbackAddresses": true
    }
  }
EOF

sa-json-template = <<-EOF
  {
    "sa": {
      "db": {
        "dbConnectFile": "{{ env "REPO_DIR" }}/test/secrets/sa_dburl",
        "maxOpenConns": 100
      },
      "ParallelismPerRPC": 20,
      "debugAddr": ":{{ env "NOMAD_PORT_debug" }}",
      "tls": {
        "caCertFile": "{{ env "REPO_DIR" }}/test/grpc-creds/minica.pem",
        "certFile": "{{ env "REPO_DIR" }}/test/grpc-creds/sa.boulder/cert.pem",
        "keyFile": "{{ env "REPO_DIR" }}/test/grpc-creds/sa.boulder/key.pem"
      },
      "grpc": {
        "address": ":{{ env "NOMAD_PORT_grpc" }}",
        "clientNames": [
          "admin-revoker.boulder",
          "ca.boulder",
          "expiration-mailer.boulder",
          "health-checker.boulder",
          "ocsp-updater.boulder",
          "orphan-finder.boulder",
          "ra.boulder",
          "sa.boulder",
          "wfe.boulder"
        ]
      },
      "features": {
        "FasterNewOrdersRateLimit": true,
        "StoreRevokerInfo": true,
        "GetAuthzReadOnly": true
      }
    },

    "syslog": {
      "stdoutlevel": 6,
      "sysloglevel": 6
    },
    "beeline": {
        "mute": true,
        "dataset": "Test"
    }
  }
EOF
