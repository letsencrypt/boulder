variable "va-remote-config" {
  type = string
}

variable "sa-config" {
  type = string
}

variable "boulder-dir" {
  type = string
}

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
    update {
      min_healthy_time = "1s"
    }
    task "mariadb" {
      driver = "docker"
      service {
        name = "boulder-mysql"
        port = "db"
      }
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
      env {
        MYSQL_ALLOW_EMPTY_PASSWORD = "yes"
      }
    }
    task "provision-mariadb" {
      driver = "raw_exec"
      lifecycle {
        hook    = "poststart"
        sidecar = false
      }
      config {
        command = "sh"
        args = [
          "-c",
          "sleep 5 && ${var.boulder-dir}/test/wait-for-it.sh boulder-mysql 3306 && ${var.boulder-dir}/test/create_db.sh"
        ]
      }
      env {
        MYSQL_CONTAINER = 1
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
      driver = "raw_exec"
      service {
        name = "remote-va"
        port = "grpc"
      }
      config {
        command = "${var.boulder-dir}/bin/boulder-remoteva"
        args = [
          "--config", "${NOMAD_ALLOC_DIR}/data/remote-va.json"
        ]
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
{{ with secret "boulder_int/issue/boulder" "alt_names=va.boulder" "format=pem" "ttl=1m" }}
{{ .Data.certificate }}
{{ end }}
EOH
        destination = "${NOMAD_SECRETS_DIR}/va/cert.pem"
        change_mode = "restart"
      }

      template {
        data        = <<EOH
{{ with secret "boulder_int/issue/boulder" "alt_names=va.boulder" "format=pem" "ttl=1m" }}
{{ .Data.private_key }}{{ end }}
EOH
        destination = "${NOMAD_SECRETS_DIR}/va/key.pem"
        change_mode = "restart"
      }

      template {
        data        = <<EOH
{{ with secret "boulder_int/issue/boulder" "alt_names=va.boulder" "format=pem" "ttl=1m" }}
{{ .Data.issuing_ca }}{{ end }}
EOH
        destination = "${NOMAD_SECRETS_DIR}/va/ca-cert.pem"
        change_mode = "restart"
      }
      env {
        BOULDER_DIR = "${var.boulder-dir}"
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
      driver = "raw_exec"
      service {
        name = "sa"
        port = "grpc"
      }
      vault {
        policies = ["nomad-cluster"]
      }
      config {
        command = "${var.boulder-dir}/bin/boulder-sa"
        args = [
          "--config", "${NOMAD_ALLOC_DIR}/data/sa.json"
        ]
      }
      template {
        data        = var.sa-config
        destination = "${NOMAD_ALLOC_DIR}/data/sa.json"
        change_mode = "restart"
      }
      env {
        BOULDER_DIR = "${var.boulder-dir}"
      }
      template {
        data        = <<EOH
{{ with secret "boulder_int/issue/boulder" "alt_names=sa.boulder" "format=pem" "ttl=1m" }}
{{ .Data.certificate }}
{{ end }}
EOH
        destination = "${NOMAD_SECRETS_DIR}/sa/cert.pem"
        change_mode = "restart"
      }

      template {
        data        = <<EOH
{{ with secret "boulder_int/issue/boulder" "alt_names=sa.boulder" "format=pem" "ttl=1m" }}
{{ .Data.private_key }}{{ end }}
EOH
        destination = "${NOMAD_SECRETS_DIR}/sa/key.pem"
        change_mode = "restart"
      }

      template {
        data        = <<EOH
{{ with secret "boulder_int/issue/boulder" "alt_names=sa.boulder" "format=pem" "ttl=1m" }}
{{ .Data.issuing_ca }}{{ end }}
EOH
        destination = "${NOMAD_SECRETS_DIR}/sa/ca-cert.pem"
        change_mode = "restart"
      }
    }
  }
}