variable "va-remote-config" { type = string }
variable "sa-config" { type = string }
variable "boulder-dir" { type = string }

job "boulder" {
  datacenters = ["dev-general"]
  type        = "service"

  group "mysql" {
    count = 1
    network {
      port "db" {
        static = 3306
      }
    }

    task "mariadb" {
      resources {
        cpu    = 10
        memory = 100
      }
      service {
        name = "boulder-mysql"
        port = "db"
      }
      env {
        MYSQL_ALLOW_EMPTY_PASSWORD = "yes"
      }
      driver = "docker"
      config {
        image   = "mariadb:10.5"
        ports   = ["db"]
        command = "mysqld"
        args = [
          "--bind-address=0.0.0.0",
          "--slow-query-log",
          "--log-output=TABLE",
          "--log-queries-not-using-indexes=ON",
        ]
      }
    }

    task "provision-mariadb" {
      lifecycle {
        hook    = "poststart"
        sidecar = false
      }
      env {
        MYSQL_CONTAINER = 1
      }
      driver = "raw_exec"
      config {
        command = "sh"
        args = [
          "-c",
          "sleep 5 && ${var.boulder-dir}/test/wait-for-it.sh boulder-mysql 3306 && ${var.boulder-dir}/test/create_db.sh"
        ]
      }
    }
  }

  group "remote-va" {
    count = 1
    network {
      port "debug" {}
      port "http" {}
      port "https" {}
      port "grpc" {}
    }

    task "server" {
      resources {
        cpu    = 10
        memory = 100
      }
      service {
        name = "remote-va"
        port = "grpc"
      }
      env {
        BOULDER_DIR = "${var.boulder-dir}"
      }
      vault {
        policies = ["nomad-cluster"]
      }
      template {
        data        = var.va-remote-config
        destination = "${NOMAD_ALLOC_DIR}/data/remote-va.json"
        change_mode = "restart"
      }
      # https://www.vaultproject.io/api-docs/secret/pki#parameters-13
      template {
        data        = <<EOH
{{ with secret "boulder_int/issue/boulder" "alt_names=va.boulder" "format=pem" "ttl=72h" }}
{{ .Data.certificate }}
{{ end }}
EOH
        destination = "${NOMAD_SECRETS_DIR}/va/cert.pem"
        change_mode = "restart"
      }
      template {
        data        = <<EOH
{{ with secret "boulder_int/issue/boulder" "alt_names=va.boulder" "format=pem" "ttl=72h" }}
{{ .Data.private_key }}{{ end }}
EOH
        destination = "${NOMAD_SECRETS_DIR}/va/key.pem"
        change_mode = "restart"
      }
      template {
        data        = <<EOH
{{ with secret "boulder_int/issue/boulder" "alt_names=va.boulder" "format=pem" "ttl=72h" }}
{{ .Data.issuing_ca }}{{ end }}
EOH
        destination = "${NOMAD_SECRETS_DIR}/va/ca-cert.pem"
        change_mode = "restart"
      }
      driver = "raw_exec"
      config {
        command = "${var.boulder-dir}/bin/boulder-remoteva"
        args = [
          "--config", "${NOMAD_ALLOC_DIR}/data/remote-va.json"
        ]
      }
    }
  }

  group "sa" {
    count = 1
    network {
      port "debug" {}
      port "grpc" {}
    }

    task "server" {
      resources {
        cpu    = 10
        memory = 100
      }
      service {
        name = "sa"
        port = "grpc"
      }
      vault {
        policies = ["nomad-cluster"]
      }
      template {
        data        = var.sa-config
        destination = "${NOMAD_ALLOC_DIR}/data/sa.json"
        change_mode = "restart"
      }
      env {
        BOULDER_DIR = "${var.boulder-dir}"
      }
      # https://www.vaultproject.io/api-docs/secret/pki#parameters-13
      template {
        data        = <<EOH
{{ with secret "boulder_int/issue/boulder" "alt_names=sa.boulder" "format=pem" "ttl=72h" }}
{{ .Data.certificate }}
{{ end }}
EOH
        destination = "${NOMAD_SECRETS_DIR}/sa/cert.pem"
        change_mode = "restart"
      }
      template {
        data        = <<EOH
{{ with secret "boulder_int/issue/boulder" "alt_names=sa.boulder" "format=pem" "ttl=72h" }}
{{ .Data.private_key }}{{ end }}
EOH
        destination = "${NOMAD_SECRETS_DIR}/sa/key.pem"
        change_mode = "restart"
      }
      template {
        data        = <<EOH
{{ with secret "boulder_int/issue/boulder" "alt_names=sa.boulder" "format=pem" "ttl=72h" }}
{{ .Data.issuing_ca }}{{ end }}
EOH
        destination = "${NOMAD_SECRETS_DIR}/sa/ca-cert.pem"
        change_mode = "restart"
      }
      driver = "raw_exec"
      config {
        command = "${var.boulder-dir}/bin/boulder-sa"
        args = [
          "--config", "${NOMAD_ALLOC_DIR}/data/sa.json"
        ]
      }
    }
  }
}