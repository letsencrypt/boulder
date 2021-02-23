# boulder-observer
A modular config driven approach to black box monitoring with Prometheus


## Usage
### Starting the `observer` daemon
```shell
$ ./observer/plugins/build.sh && go run ./cmd/boulder-observer/main.go -config test/config-next/observer.yaml
Building plugins:
⚙️ observer/plugins/dns.so
✅dns.so
⚙️ observer/plugins/http.so
✅http.so
OK
I191418 main ksKu7w4 Versions: main=(Unspecified Unspecified) Golang=(go1.15.7) BuildHost=(Unspecified)
I191418 main o9me0QI Initializing boulder-observer daemon from config: test/config-next/observer.yaml
I191420 main wv7tug0 HTTP monitor "https://letsencrypt.org-200" succeeded while taking:=120.900665ms
I191422 main ss-hzQ8 HTTP monitor "https://letsencrypt.org-200" succeeded while taking:=23.051998ms
I191424 main -fD46gg HTTP monitor "https://letsencrypt.org-200" succeeded while taking:=23.419121ms
I191426 main urmy8AM HTTP monitor "https://letsencrypt.org-200" succeeded while taking:=23.875478ms
I191428 main qaGe0Qc DNS monitor "udp-8.8.8.8:53-google.com-A" succeeded while taking:=5.088261ms
I191428 main i677rw0 DNS monitor "tcp-8.8.8.8:53-google.com-A" succeeded while taking:=5.156114ms
I191428 main ooyq_Qo DNS monitor "udp-owen.ns.cloudflare.com:53-letsencrypt.org-A" succeeded while taking:=15.858563ms
```

### Help
```shell
$ go run ./cmd/boulder-observer/main.go -help
main:
  -config string
        Path to boulder-observer configuration file (default "config.yaml")
```
## Configuration
```yaml
debugAddr: 8040
syslog: 
  stdoutlevel: 6
  sysloglevel: 6
timeout: 5
monitors: []
```

### Monitors

#### Using the DNS plugin
```yaml
monitors:
  - 
    enabled: true
    period: 1
    plugin:
      name: DNS
      path: "./cmd/boulder-observer/observer/plugins/dns.so"
    settings:
      qproto: udp
      qrecurse: false
      qname: letsencrypt.org
      qtype: A
      qserver: "owen.ns.cloudflare.com:53"
```

#### Using the HTTP plugin
```yaml
monitors:
  - 
    enabled: true
    period: 1
    plugin:
      name: HTTP
      path: "./cmd/boulder-observer/observer/plugins/http.so"
    settings: 
      url: https://letsencrypt.org
      rcode: 200
```

### Plugins
**Building plugins**
```shell
$ ./observer/plugins/build.sh
Building plugins:
⚙️ observer/plugins/dns.so
✅dns.so
⚙️ observer/plugins/http.so
✅http.so
OK
```