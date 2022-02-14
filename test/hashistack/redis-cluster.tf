// datacenter is used for the datacenter field when connecting to both Nomad and
// Consul.
variable "datacenter" {
  type    = string
  default = "dev-general"
}

// region is the region used when connecting to Consul to both Nomad and Consul.
variable "region" {
  type    = string
  default = "global"
}

// await-service-name is commented in the job specification.
variable "await-service-name" {
  type    = string
  default = "redis-cluster-await"
}

// dest-service-name is commented in the job specification.
variable "dest-service-name" {
  type    = string
  default = "redis-cluster"
}

// primary-count is commented in the job specification.
variable "primary-count" {
  type    = number
  default = 3
}

// replica-count is commented in the job specification.
variable "replica-count" {
  type    = number
  default = 3
}

provider "consul" {
  address    = "127.0.0.1:8501"
  datacenter = var.datacenter
  scheme     = "https"
  ca_file    = "tls/consul/consul-agent-ca.pem"
  cert_file  = "tls/attache/consul/dev-general-client-consul-0.pem"
  key_file   = "tls/attache/consul/dev-general-client-consul-0-key.pem"
}

provider "nomad" {
  address = "http://127.0.0.1:4646"
  region  = var.region
}

resource "consul_keys" "redis-cluster" {
  datacenter = var.datacenter

  key {
    path  = "service/${var.dest-service-name}/scaling"
    value = <<-EOF
      primary-count: ${var.primary-count}
      replica-count: ${var.replica-count}
    EOF
  }
}

resource "nomad_job" "redis-cluster" {
  jobspec = file("${path.module}/redis-cluster.hcl")

  hcl2 {
    enabled = true
    vars = {
      await-service-name         = var.await-service-name
      dest-service-name          = var.dest-service-name
      primary-count              = var.primary-count
      replica-count              = var.replica-count
      redis-username             = "replication-user"
      redis-password             = "435e9c4225f08813ef3af7c725f0d30d263b9cd3"
      redis-tls-cacert           = <<-EOF
        -----BEGIN CERTIFICATE-----
        MIIDSzCCAjOgAwIBAgIIAg26dvKrbYkwDQYJKoZIhvcNAQELBQAwIDEeMBwGA1UE
        AxMVbWluaWNhIHJvb3QgY2EgMDIwZGJhMCAXDTIxMTAyMzAyMTUxOVoYDzIxMjEx
        MDIzMDMxNTE5WjAgMR4wHAYDVQQDExVtaW5pY2Egcm9vdCBjYSAwMjBkYmEwggEi
        MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDMlMwTusfIaEz7eB8RZua6kW81
        1G5DzvO8X9GAi8mdlqoOuSmSvHNz59Vn0lUZ7H1NwyAXqPm7FgYrGzAPBKJ+Kkw9
        drJJLoeSWPtFT9lISbl9qRpYg99aWzWfuEdKYJDa5woZLoQEaARW88TcCB44wLtK
        yJpakMJZKV5gXqfpfSARyQPLsP/jirVhD+bNEs3sBBxw2WMtDdVS12V1soD2iKA5
        wTiKNjjpbyea6Q5zWcjFq2K8upx65hL75tdkHaYCqLZeeq/ciglGvXDKenZMMSY9
        Oz4qUDhxWTcb15zyolT8fQ9QdZqvBoOD6WBuWTNXbnT3zISiZGAAPQgdv9d7AgMB
        AAGjgYYwgYMwDgYDVR0PAQH/BAQDAgKEMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggr
        BgEFBQcDAjASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBQP6Fb0a7XEzSGV
        PZY5GjjuWKMQrTAfBgNVHSMEGDAWgBQP6Fb0a7XEzSGVPZY5GjjuWKMQrTANBgkq
        hkiG9w0BAQsFAAOCAQEASfe9zRlpIXHy4+mp1PIpjGjJjk0NhPOcoN8B2vCqYWsJ
        nnfl9zfORkWPL6PgiXWqS6nNC+iqRFBWphaRqtSle0j+4NLFnmmOMXI/NlCjAvTH
        6TNJ/H0nHlJ9p3Ui9a5MvZ8I/dOJLrFDX4/d9Lg76txKhFJBzXvxd9PSVKPJvnfx
        x3aare5fkXy+JlZwP8FhbzIwVTmHGPxKEUCbImhmailXTfLTmm+bS1CW2OrOnlSn
        ZPlEA8N1Y8ogNZQf2v65QCT7k64a1IuEA7XcH+W4+JhRAPPp1NujMTbeo855gMMm
        D6LXhbMEV2jO6Yfqgr2H+fmiWq3nILj/XBSTEYNBqQ==
        -----END CERTIFICATE-----

      EOF
      redis-tls-cert             = <<-EOF
        -----BEGIN CERTIFICATE-----
        MIIDJzCCAg+gAwIBAgIIEguoVcAkRXwwDQYJKoZIhvcNAQELBQAwIDEeMBwGA1UE
        AxMVbWluaWNhIHJvb3QgY2EgMDIwZGJhMB4XDTIxMTIwNjIxNTIwOFoXDTI0MDEw
        NTIxNTIwOFowFDESMBAGA1UEAxMJMTI3LjAuMC4xMIIBIjANBgkqhkiG9w0BAQEF
        AAOCAQ8AMIIBCgKCAQEAsBrTn0RmwyiZlOxB779Vam0M96SJbyf0w+EDVZXqVjuG
        dJxXsuSuEqF8fDZIycsRji+1WQ9IG5er4A/0TFUAxE7gFzag27hk0Y7vRnzrZi3P
        FivekkP1r4SZuIgF2UnCfZcsMOMkBGJ8t36DygaDEOJ+eu+rPR6nlznbOtYlJOtY
        NUZh3OZ927dBPlyAi8rAdLvHNAjYZWYL8mlNU9WoI+JKE9iDoQnFlJSaNtld7RsN
        TzIOC/CaVjBjmCjgf70SirFLXk23xC44gOywRuO+Oo9dMRjEY2SjX1/9FKgSsyRQ
        nQRTBzMqq4Q3L0qTgrnNKRT9Fsi+aiMtza5CAXoYbQIDAQABo3EwbzAOBgNVHQ8B
        Af8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMAwGA1UdEwEB
        /wQCMAAwHwYDVR0jBBgwFoAUD+hW9Gu1xM0hlT2WORo47lijEK0wDwYDVR0RBAgw
        BocEfwAAATANBgkqhkiG9w0BAQsFAAOCAQEAhXQiQrK5nGOJRKBwePXl84PzWO0y
        z2MEOJmmZcmom1uRW/LlInTRXbX1s8wkFlCkSsGtW+IE4uF8WmKrKR+/shXzVRm2
        TfYWU07GuJhg768BONCVqC2K8kWn2TwSAz6im1rPsQaoQcjlD1F3IrYDYQvxP4cz
        5mPdgHDpSPzsfkAghxr6wWr8VHnUSEiIF+WzIjne0lsW8Mscs2iQSU+vy9/5sxxd
        zwieFZvgQAysNs4MVW4XUvQbxe1bgrUFTgFJlrYn1axZJxoxhPdyUzkkzDi5l7GR
        tdmiwilYpqjGVUUOmchowYSHN4PjLCE7ZINlhsnUhcrTqLjpQRFsW8oyWg==
        -----END CERTIFICATE-----

      EOF
      redis-tls-key              = <<-EOF
        -----BEGIN RSA PRIVATE KEY-----
        MIIEowIBAAKCAQEAsBrTn0RmwyiZlOxB779Vam0M96SJbyf0w+EDVZXqVjuGdJxX
        suSuEqF8fDZIycsRji+1WQ9IG5er4A/0TFUAxE7gFzag27hk0Y7vRnzrZi3PFive
        kkP1r4SZuIgF2UnCfZcsMOMkBGJ8t36DygaDEOJ+eu+rPR6nlznbOtYlJOtYNUZh
        3OZ927dBPlyAi8rAdLvHNAjYZWYL8mlNU9WoI+JKE9iDoQnFlJSaNtld7RsNTzIO
        C/CaVjBjmCjgf70SirFLXk23xC44gOywRuO+Oo9dMRjEY2SjX1/9FKgSsyRQnQRT
        BzMqq4Q3L0qTgrnNKRT9Fsi+aiMtza5CAXoYbQIDAQABAoIBAGWkdjRcxHsrucks
        u7nm0yQEIRHmE7TmeO19t/D0ADcZUDeJ7UxBlP8H2dPPeR+PZ2iLvL3Uhif22KsQ
        Sk6sWS70335Gd32Z5gbV2uDyROPK2NXRKDt/ohRWEmthhw6s9eaLFGR7FVS6i4VV
        Ljeynn9mWt4V6t3yDYTJTfGdm/68KV7UJvD6TYnfs3MNeYsq0MsfXWWfsbVVj7CP
        en7XIkh+9R3qNmZgtIb1jJXMVCzEuK/r0DezW5FRUFbS19Cp/DhIvjTICZXURt7p
        uY3zYlWHpziTBnAgFz+6YQ1doV9GV1mKqqa2Hx+L9eml3vruc3p0E2uh8xNXcXKH
        cWnsrrkCgYEAw/EuXHTM4wroFb17PGVIwNd1BrT0QzkJ11G/I13o9WUITAyj6Y4k
        SXxl3J8faGRPPHXXgSswc9C3cGnkP3Py4zrZXT/Drf3Cly9I70ht8pQHckN56P8y
        uNid/Se7IWUy2NObQxazMu7G7Szc3qFqaU+/t7Rjby4pIQeVmFCcdhMCgYEA5hUW
        c9maBxKce8PLREgL98Akpu8z09mYM8YmjKyQVjfdkX5Igrv9b85tHbNHYUHc+5On
        us7HMagasJyFhzykLylCpFpn4p4H6/XE4tJhtOeHfjVNwgt6iggpSPqsVPYgM8xE
        LSBluSMWuQ8IHf4eK+1QkzPunEi5TbDoMSj7B38CgYBnT/Rs5VzeXXLPe6/NwW2h
        2DipB6I/C4UH1d9dC3f4Y4QDbSrDy6GQaZnfwLqztSgeLdgqEBalCiieigbB+iXX
        78CKLUPEqqb+Rf1DxUHLhIeElNVjp6Mb2YM75sYBLrWno7MapY5ozYNvrJbsf9l2
        m4jvmJpRFdqzwqb6v44vpwKBgQChv+d18F9pY3shQydOTHwlYy4hMX61C38FvuLw
        +IvMISAiHa5qQjDMfkmVnKisxfnN3yMGoEHHNg/1Y0Q4K7ic8xvHoUrxNPoKt0//
        ybkozbAiWOTeauVtzoj/pkKqxBEleQ/gzarVucZKuTeSpkidxwtjQRoZQsMKzDif
        /thjjwKBgAN33iDDck6UGI0sWJE9aDT/X5u7p7G0AKvB7nlUKTFaMGwXLwZ00Ug6
        B6uoa2NUtqh4wWV1D43vzFzz4pKrsXlYyapTzI3Qw7lQ8SWOKcheAYDItFfrIdw1
        seI2E/pQAa8Hk7LWdm7auECu17avSc3RQ3uINnNSZQVFAc7qESjV
        -----END RSA PRIVATE KEY-----

      EOF
      redis-config-template      = <<-EOF
        user default off
        masteruser replication-user
        masterauth {{ env "redis-password" }}
        user replication-user  on +@all ~* >{{ env "redis-password" }}
        # Working Directory
        dir {{ env "NOMAD_ALLOC_DIR" }}/data/
        daemonize no
        # TCP Port (0 to disable)
        port 0
        bind {{ env "NOMAD_IP_db" }}
        tls-port {{ env "NOMAD_PORT_db" }}
        tls-ca-cert-file {{ env "NOMAD_ALLOC_DIR" }}/data/redis-tls/ca-cert.pem
        tls-cert-file {{ env "NOMAD_ALLOC_DIR" }}/data/redis-tls/cert.pem
        tls-key-file {{ env "NOMAD_ALLOC_DIR" }}/data/redis-tls/key.pem
        tls-cluster yes
        tls-replication yes
        cluster-enabled yes
        cluster-node-timeout 5000
        cluster-config-file {{ env "NOMAD_ALLOC_DIR" }}/data/nodes.conf
        cluster-require-full-coverage no
        # Enable snapshotting and save a snapshot every 60 seconds if at least one key has changed.
        save 60 1
        maxmemory-policy noeviction
        loglevel warning
        # List of renamed commands comes from:
        # https://www.digitalocean.com/community/tutorials/how-to-secure-your-redis-installation-on-ubuntu-18-04
        rename-command BGREWRITEAOF ""
        rename-command BGSAVE ""
        rename-command CONFIG ""
        rename-command DEBUG ""
        rename-command DEL ""
        rename-command FLUSHALL ""
        rename-command FLUSHDB ""
        rename-command KEYS ""
        rename-command PEXPIRE ""
        rename-command RENAME ""
        rename-command SAVE ""
        rename-command SHUTDOWN ""
        rename-command SPOP ""
        rename-command SREM ""

      EOF
      attache-redis-tls-cert     = <<-EOF
        -----BEGIN CERTIFICATE-----
        MIIDJzCCAg+gAwIBAgIIH6kXr5uW/6gwDQYJKoZIhvcNAQELBQAwIDEeMBwGA1UE
        AxMVbWluaWNhIHJvb3QgY2EgMDIwZGJhMB4XDTIxMTIwNjIxNTA0NloXDTI0MDEw
        NTIxNTA0NlowFDESMBAGA1UEAxMJMTI3LjAuMC4xMIIBIjANBgkqhkiG9w0BAQEF
        AAOCAQ8AMIIBCgKCAQEA+KjVq9tqg6Q8RAAM+FtfYEp+ge31wnwBieLv/CGnEaZS
        QAd9zZqSjJPhrgCAT3qanBXFgT23vjV9ycjj8gkUpWuVRaeeF4/RlT3A9G5FElBn
        2kfX2UefBg2N4LB6vBUFdk0Eosk6eOGmO+BFoQ6Z8SljIFfDjdoRNrSsWhxWgNw/
        SsIot23gk7mvVOyEZ9Pnsua36xE/rClL4ywXs3LeykdQTwWVE86LOi+IBWTh9V+Q
        AR7j59AYpFl3DIkZGnGSYb5ZluKMlPL8SG+UqqH7qdRJIiwEg1Z0cNcBX17+j6QC
        CA9C51PGhg6/+yHbHgackEvdgGW25vRyvU0wxGNkSwIDAQABo3EwbzAOBgNVHQ8B
        Af8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMAwGA1UdEwEB
        /wQCMAAwHwYDVR0jBBgwFoAUD+hW9Gu1xM0hlT2WORo47lijEK0wDwYDVR0RBAgw
        BocEfwAAATANBgkqhkiG9w0BAQsFAAOCAQEAh5ZS+cogsguME6tfbJyhBy7bPfUP
        5zXr22Xuw41FWBIytGDwpcslnyxhYAX+ngCyNu5pzxgC3TKW5Jri5wPoMJlaFeya
        keKZShbzJEQIjjGLWbxl9ojsrrKuesgz5XqKt06VVC/RoiVX5ybD1IGv7nSQdWVn
        Q8ZYxmEcHrPn2juXHF4yguucEwuXyZnlWVGKrFchAMqMVHwSuvMMNLvTfsOWTuqU
        KkDkLTeOacmvTsb7J/yyXxzJzzpwmpPIrgO6Igz4zSADp4ErMk+6MduZQKTA3rhX
        r53Jtmv+CLORODWe5+Cw38dJYlsRdyf7ShPuJQDEDOEFSKVFHJEOU9F1MQ==
        -----END CERTIFICATE-----

      EOF
      attache-redis-tls-key      = <<-EOF
        -----BEGIN RSA PRIVATE KEY-----
        MIIEpAIBAAKCAQEA+KjVq9tqg6Q8RAAM+FtfYEp+ge31wnwBieLv/CGnEaZSQAd9
        zZqSjJPhrgCAT3qanBXFgT23vjV9ycjj8gkUpWuVRaeeF4/RlT3A9G5FElBn2kfX
        2UefBg2N4LB6vBUFdk0Eosk6eOGmO+BFoQ6Z8SljIFfDjdoRNrSsWhxWgNw/SsIo
        t23gk7mvVOyEZ9Pnsua36xE/rClL4ywXs3LeykdQTwWVE86LOi+IBWTh9V+QAR7j
        59AYpFl3DIkZGnGSYb5ZluKMlPL8SG+UqqH7qdRJIiwEg1Z0cNcBX17+j6QCCA9C
        51PGhg6/+yHbHgackEvdgGW25vRyvU0wxGNkSwIDAQABAoIBAB/cGgx7/4jAaUxZ
        KVBE/NJsmQryv1Nc6iGNpywJ78sOIWm8y/yk+nPymq7dt5L3ZYnsLDMkAj/nwKcz
        Cym+yhtrzmNvV40zSyoxEGEBI+51yOip3dkkGRcAc5Y/Zmpk0x9WPOrSl6BXYSI4
        2RMKuOSyZdYGCLNLJnt46MBe8yJtVTK+VQnZqgTxtVjlvVH0MoLfd0j8VFwW/pak
        3Cv50N5fduSBZIbEH+KTBfjqfcT9bAcoLSd1HA11zv9bjlHKPpA8F748FeNvwgwe
        lyp6YAcmVaGY+FcKBQdStGiBox9h3XqjHUOgdDWVwhezAF8mNr48sqTE2AEoGf1r
        fP8JJKkCgYEA+mVPEYMXU29nj6NnWXOMA0pN8dvWvLJLTer+XAkEnVOeRRR4qb01
        whX4WyjE+4HykZBFOqspe9V+hGwKqjOysRIlNRfu2nKo5SzQT+1V5+okzEJKWe3o
        2J/L0kJwjdCTt64G7VJhCFLQYI4AMjXtFvTEGDDSkypgJtzBfuDROJcCgYEA/jmT
        5sFCKNIizIllg/xf5uA6kFPWE5/bxrzl6T+57exUjlrEQJsU2SgHeg6ULBlkPlrF
        eBpYRpK9Lazin6O/kg92wPnhjWGPlgeC/4/qePr4yRBWbwrK3ddVCCyxHJn2E2YO
        joJURrCL6UZhKYbrZfK9jbf6Z/9IIpy6U9IBlG0CgYEAkWNjnrJ0R9Dm2+MwLiNG
        R97MFUPlkpkf2nU5De16jXMw8cFqMnyXi0NAeoXYooSYeObBG8iohKu5E2C8bIkq
        F2CG1CY6XQK4iKEVr2MKP2eXyDYxf7gBPE7EhShovB9AtiVJBmGPz8puDbJF8OGY
        8XxbpAQtMKApRkdl3qrhMK8CgYBND/MPbeG6Mgiua6/EFIqVl77o5SDtjfW3BqfC
        zrhzsMHo7Qa0ds4ZDZNGooiz3XaPmEBnqcS8j9qcr916es6lXd6nnJeMndhCqEBD
        a8KtrZYgjL1Gp8Ta/l0ePz3o55q6QqOC+2rEitu+eMEXL3jHzI89GFnlkHKzW0L4
        CZ7E+QKBgQCFuXf6evp56eS0440jZbQRtTw9fRodbpTkEJcncwIEHb5CyBQR7KG3
        icajrMNqHmdqSTZE2x/t/G2IyQ7qdWc4oHV7fHdavTRIED1qnPttihc7LX+56q6h
        ptuRGx51m1nbP0LU+0H5vzZy712aCPtS92/n1BqKHOdTR6zYViR33w==
        -----END RSA PRIVATE KEY-----

      EOF
      consul-tls-ca-cert = <<-EOF
        -----BEGIN CERTIFICATE-----
        MIIC7jCCApSgAwIBAgIRAN4DUzSw7n5g8dkMKNlRYikwCgYIKoZIzj0EAwIwgbkx
        CzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDQTEWMBQGA1UEBxMNU2FuIEZyYW5jaXNj
        bzEaMBgGA1UECRMRMTAxIFNlY29uZCBTdHJlZXQxDjAMBgNVBBETBTk0MTA1MRcw
        FQYDVQQKEw5IYXNoaUNvcnAgSW5jLjFAMD4GA1UEAxM3Q29uc3VsIEFnZW50IENB
        IDI5NTEwNTg3OTU2OTQ0NjE2NDk3ODAzNzc2MTQ1MDU5Mjc4OTAzMzAeFw0yMjAx
        MTkwMDAzMzFaFw0yNzAxMTgwMDAzMzFaMIG5MQswCQYDVQQGEwJVUzELMAkGA1UE
        CBMCQ0ExFjAUBgNVBAcTDVNhbiBGcmFuY2lzY28xGjAYBgNVBAkTETEwMSBTZWNv
        bmQgU3RyZWV0MQ4wDAYDVQQREwU5NDEwNTEXMBUGA1UEChMOSGFzaGlDb3JwIElu
        Yy4xQDA+BgNVBAMTN0NvbnN1bCBBZ2VudCBDQSAyOTUxMDU4Nzk1Njk0NDYxNjQ5
        NzgwMzc3NjE0NTA1OTI3ODkwMzMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASs
        V95+qGSD9fDZdbC621bw3qxJ3jdlLuXvc3bmBxYjROt5zBs9e8M1DO2M3G97scuT
        R3z+len7Tk1zNMq7Bbcno3sweTAOBgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUw
        AwEB/zApBgNVHQ4EIgQgrFJbvMZUANDyAKRgOTF8qEoEKJz0q6YP9H6z//PlKP8w
        KwYDVR0jBCQwIoAgrFJbvMZUANDyAKRgOTF8qEoEKJz0q6YP9H6z//PlKP8wCgYI
        KoZIzj0EAwIDSAAwRQIgQYpMKdsbm7nZ9L+B5EPWM2j/QAALYXqoTJZKbQpT1xkC
        IQC1fQi4d3fKX/B1+FVl7HFXLNl3HZc4aG0ZHLHDzRxtOw==
        -----END CERTIFICATE-----

      EOF
      attache-consul-tls-cert    = <<-EOF
        -----BEGIN CERTIFICATE-----
        MIICqzCCAlKgAwIBAgIQTzAKktzREOLGCmfXQ2ZIeDAKBggqhkjOPQQDAjCBuTEL
        MAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNpc2Nv
        MRowGAYDVQQJExExMDEgU2Vjb25kIFN0cmVldDEOMAwGA1UEERMFOTQxMDUxFzAV
        BgNVBAoTDkhhc2hpQ29ycCBJbmMuMUAwPgYDVQQDEzdDb25zdWwgQWdlbnQgQ0Eg
        Mjk1MTA1ODc5NTY5NDQ2MTY0OTc4MDM3NzYxNDUwNTkyNzg5MDMzMB4XDTIyMDEx
        OTAyMTk0N1oXDTIzMDExOTAyMTk0N1owJDEiMCAGA1UEAxMZY2xpZW50LmRldi1n
        ZW5lcmFsLmNvbnN1bDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABPI96gOhYdej
        PB3pBPmEGe371/ozv8LIfWPGm0KknIlgepeXgBaUGuj47LJIJt7ACtdroLLMgNwx
        mJYEkUb4fmmjgc8wgcwwDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUF
        BwMCBggrBgEFBQcDATAMBgNVHRMBAf8EAjAAMCkGA1UdDgQiBCAKhLdW6OZ1C3FP
        jl4hYfED/I+MJSK6K88CGhTEvGnkxzArBgNVHSMEJDAigCCsUlu8xlQA0PIApGA5
        MXyoSgQonPSrpg/0frP/8+Uo/zA1BgNVHREELjAsghljbGllbnQuZGV2LWdlbmVy
        YWwuY29uc3Vsgglsb2NhbGhvc3SHBH8AAAEwCgYIKoZIzj0EAwIDRwAwRAIgdE3A
        V+dDIRQDh+UvHAtKZ/jZN9Ngiog+WArXscpC58ICIBsz7I2tlyPws0UIrvmkkaja
        wE1fWsYqIBM61rsbo3C+
        -----END CERTIFICATE-----

      EOF
      attache-consul-tls-key     = <<-EOF
        -----BEGIN EC PRIVATE KEY-----
        MHcCAQEEIEJ1/M9V4eoCJG6NJfT/IWYLJWT/lA/gzMa31yDm8dAtoAoGCCqGSM49
        AwEHoUQDQgAE8j3qA6Fh16M8HekE+YQZ7fvX+jO/wsh9Y8abQqSciWB6l5eAFpQa
        6Pjsskgm3sAK12ugssyA3DGYlgSRRvh+aQ==
        -----END EC PRIVATE KEY-----

      EOF
    }
  }
}
