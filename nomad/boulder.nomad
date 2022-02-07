variable "await-dependency-sh-template" {
  type = string
}

variable "va-remote-json-template" {
  type = string
}

variable "sa-json-template" {
  type = string
}

variable "repo-dir" {
  type = string
}

job "boulder" {
  datacenters = ["dev-general"]
  type        = "service"

  group "boulder-mysql" {
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
          "sleep 5 && ${var.repo-dir}/test/wait-for-it.sh boulder-mysql 3306 && ${var.repo-dir}/test/create_db.sh"
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
        command = "$${HOME}/repos/boulder/bin/boulder-remoteva"
        args = [
          "--config", "${NOMAD_ALLOC_DIR}/data/remote-va.json"
        ]
      }
      template {
        data        = var.va-remote-json-template
        destination = "${NOMAD_ALLOC_DIR}/data/remote-va.json"
        change_mode = "restart"
      }
      env {
        REPO_DIR = "${var.repo-dir}"
      }
    }
  }

  group "sa" {
    count = 1
    network {
      port "debug" {}
      port "grpc" {}
    }
    task "sa-await-db" {
      driver = "raw_exec"
      lifecycle {
        hook    = "prestart"
        sidecar = false
      }
      config {
        command = "${NOMAD_ALLOC_DIR}/data/await_dependency.sh"
      }
      env {
        DEPENDENCY_NAME = "boulder-mysql"
      }
      template {
        data        = var.await-dependency-sh-template
        destination = "${NOMAD_ALLOC_DIR}/data/await_dependency.sh"
        change_mode = "noop"
      }
    }
    task "server" {
      driver = "raw_exec"
      service {
        name = "sa"
        port = "grpc"
      }
      config {
        command = "$${HOME}/repos/boulder/bin/boulder-sa"
        args = [
          "--config", "${NOMAD_ALLOC_DIR}/data/sa.json"
        ]
      }
      template {
        data        = var.sa-json-template
        destination = "${NOMAD_ALLOC_DIR}/data/sa.json"
        change_mode = "restart"
      }
      env {
        REPO_DIR = "${var.repo-dir}"
      }
    }
  }

 group "sa" {
    count = 1
    network {
      port "debug" {}
      port "grpc" {}
    }
    task "sa-await-db" {
      driver = "raw_exec"
      lifecycle {
        hook    = "prestart"
        sidecar = false
      }
      config {
        command = "${NOMAD_ALLOC_DIR}/data/await_dependency.sh"
      }
      env {
        DEPENDENCY_NAME = "boulder-mysql"
      }
      template {
        data        = var.await-dependency-sh-template
        destination = "${NOMAD_ALLOC_DIR}/data/await_dependency.sh"
        change_mode = "noop"
      }
    }
    task "server" {
      driver = "raw_exec"
      service {
        name = "sa"
        port = "grpc"
      }
      config {
        command = "$${HOME}/repos/boulder/bin/boulder-sa"
        args = [
          "--config", "${NOMAD_ALLOC_DIR}/data/sa.json"
        ]
      }
      template {
        data        = var.sa-json-template
        destination = "${NOMAD_ALLOC_DIR}/data/sa.json"
        change_mode = "restart"
      }
      env {
        REPO_DIR = "${var.repo-dir}"
      }
    }
  }
}