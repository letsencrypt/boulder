# boulder-observer
A modular config driven approach to black box monitoring with
Prometheus.

## Usage

### Options
```shell
$ go run ./cmd/boulder-observer/main.go -help
  -config string
        Path to boulder-observer configuration file (default "config.yml")
```

### Starting the boulder-observer daemon
```shell
$ go run ./cmd/boulder-observer/main.go -config test/config-next/observer.yml
I185326 main _KzylQI Versions: main=(Unspecified Unspecified) Golang=(go1.16.2) BuildHost=(Unspecified)
I185326 main q_D84gk Initializing boulder-observer daemon from config: test/config-next/observer.yml
I185326 main 7aq68AQ all monitors passed validation
I185328 main 9fmV0AM kind=[HTTP] result=[true] duration=[0.131400] name=[https://letsencrypt.org-[200]]
I185328 main xrWn-wg kind=[HTTP] result=[true] duration=[0.264118] name=[http://letsencrypt.org/FOO-[200 404]]
I185330 main kun_-wY kind=[HTTP] result=[true] duration=[0.024320] name=[https://letsencrypt.org-[200]]
I185330 main 59SEzwg kind=[HTTP] result=[true] duration=[0.046738] name=[http://letsencrypt.org/FOO-[200 404]]
I185331 main wNjHxw8 kind=[DNS] result=[false] duration=[0.000007] name=[udp-2606:4700:4700::1111:53-google.com-A]
I185331 main 9ezMXAA kind=[DNS] result=[false] duration=[0.000021] name=[tcp-2606:4700:4700::1111:53-google.com-A]
I185331 main 7tWG5Qo kind=[DNS] result=[true] duration=[0.006060] name=[udp-1.1.1.1:53-google.com-A]
I185331 main 0MnQjwI kind=[DNS] result=[true] duration=[0.008671] name=[tcp-1.1.1.1:53-google.com-A]
I185331 main oYD05wQ kind=[DNS] result=[true] duration=[0.015981] name=[udp-owen.ns.cloudflare.com:53-letsencrypt.org-A]
I185331 main zJaK0gE kind=[DNS] result=[true] duration=[0.024325] name=[tcp-owen.ns.cloudflare.com:53-letsencrypt.org-A]
I185332 main zvftBQA kind=[HTTP] result=[true] duration=[0.024269] name=[https://letsencrypt.org-[200]]
I185332 main w_Ck9A0 kind=[HTTP] result=[true] duration=[0.047069] name=[http://letsencrypt.org/FOO-[200 404]]
I185334 main _cPGpgM kind=[HTTP] result=[true] duration=[0.023966] name=[https://letsencrypt.org-[200]]
I185334 main krvDoAs kind=[HTTP] result=[true] duration=[0.047156] name=[http://letsencrypt.org/FOO-[200 404]]
I185336 main nJrE8Qs kind=[DNS] result=[false] duration=[0.000009] name=[tcp-2606:4700:4700::1111:53-google.com-A]
I185336 main m-6pwQI kind=[DNS] result=[false] duration=[0.000008] name=[udp-2606:4700:4700::1111:53-google.com-A]
I185336 main _u-sgAI kind=[DNS] result=[true] duration=[0.004496] name=[udp-8.8.8.8:53-google.com-A]
I185336 main 1a-5uAg kind=[DNS] result=[true] duration=[0.005195] name=[udp-1.1.1.1:53-google.com-A]
I185336 main 0c7k6g0 kind=[DNS] result=[true] duration=[0.007354] name=[tcp-8.8.8.8:53-google.com-A]
I185336 main _uLH2Ak kind=[DNS] result=[true] duration=[0.008231] name=[tcp-1.1.1.1:53-google.com-A]
I185336 main 68iH-gk kind=[DNS] result=[true] duration=[0.012076] name=[udp-owen.ns.cloudflare.com:53-letsencrypt.org-A]
I185336 main mbnX8Ao kind=[DNS] result=[true] duration=[0.017215] name=[tcp-owen.ns.cloudflare.com:53-letsencrypt.org-A]
I185336 main uPW9NgA kind=[HTTP] result=[true] duration=[0.023477] name=[https://letsencrypt.org-[200]]
I185336 main yJft8wk kind=[HTTP] result=[true] duration=[0.046534] name=[http://letsencrypt.org/FOO-[200 404]]
```

## Configuration
Configuration is provided via a YAML file.

`debugaddr`: is the Prometheus scrape port expressed as `:` + `port
number`

`syslog`: a map of log levels for `stdoutlevel` and `sysloglevel`
```text
  0: EMERG
  1: ALERT
  2: CRIT
  3: ERR
  4: WARN
  5: NOTICE
  6: INFO
  7: DEBUG
```

`monitors`: a list of monitors, see [configuration/monitors](#monitors)

example:
```yaml
debugaddr: :8040
syslog:
  stdoutlevel: 6
  sysloglevel: 6
monitors:
  -
    ...
```

### Monitors
`period`: the interval, in seconds, to attempt a query/ request

`kind`: the kind of prober to use for the query/ request

`settings:` is map of Prober settings, the schema for which is
determined by the prober. See [probers/DNS](#DNS) and
[probers/HTTP](#HTTP).

example:
```yaml
monitors:
  - 
    period: 5s
    kind: DNS
    settings:
        ...
```
### Probers

#### DNS
`protocol`: `udp` or `tcp`

`server`: (`hostname` or `ipv4/6 address`) + `port` (e.g.
`example.com:53` or `1.1.1.1:53` or `2606:4700:4700::1111:53`)

`recurse`: `true` if recursive resolution is desired else `false`

`query_name`: `name` to query (e.g. `example.com`)

`query_type`: record type to query, supported options are: `A`, `AAAA`,
`TXT`, or `CAA`

example:
```yaml
monitors:
  - 
    period: 5s
    kind: DNS
    settings:
      protocol: tcp
      server: owen.ns.cloudflare.com:53
      recurse: false
      query_name: letsencrypt.org
      query_type: A
```

#### HTTP
`url`: `scheme` + `hostname` to send a request to (e.g.
https://example.com)

`rcodes`: list of expected 'successful' HTTP response codes

example:
```yaml
monitors:
  - 
    period: 2s
    kind: HTTP
    settings: 
      url: http://letsencrypt.org/FOO
      rcodes: [200, 404]
```

## Metrics
Observer provides the following metrics.

### obs_monitors
Count of configured monitors.

**Labels:**

`name`: name of the monitor

`type`: type of prober the monitor is configured to use

`valid`: whether the monitor configuration was valid

### obs_observations
Time taken, in seconds, for a monitor to perform a query/ request.

**Labels:**

`name`: name of the monitor

`type`: type of prober the monitor is configured to use

`result`: whether the query/ request was successful

**Bucketed response times:**

`.1, .25, .5, 1, 2.5, 5, 7.5, 10, 15, 30, 45`

## Development

### Starting Prometheus locally
Please note, this requires a local prometheus binary.
```shell
prometheus --config.file=boulder/test/prometheus/prometheus.yml
```

### Viewing metrics locally
When developing with a local prometheus instance, you can use this link
to view metrics:
[link](http://0.0.0.0:9090/graph?g0.expr=sum%20by(name)%20(%0Arate(obs_observations_bucket%7Bresult%3D%22true%22%7D%5B1m%5D)%0A)&g0.tab=0&g0.stacked=0&g0.range_input=1h&g1.expr=sum%20by(name)%20(%0Arate(obs_observations_bucket%7Bresult%3D%22false%22%7D%5B1m%5D)%0A)&g1.tab=0&g1.stacked=0&g1.range_input=1h&g2.expr=count%20by(valid)%20(%0Aobs_monitors%7Bvalid%3D%22true%22%7D%0A)&g2.tab=0&g2.stacked=0&g2.range_input=1h)