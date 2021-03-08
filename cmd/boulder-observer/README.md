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
I142601 main ksKu7w4 Versions: main=(Unspecified Unspecified) Golang=(go1.15.7) BuildHost=(Unspecified)
I142601 main q_D84gk Initializing boulder-observer daemon from config: test/config-next/observer.yml
I142603 main o4Cp-Q0 type=[HTTP] result=[true] duration=[0.123472] name=[http://letsencrypt.org-200]
I142603 main n4iSrAM type=[HTTP] result=[true] duration=[0.123751] name=[https://letsencrypt.org-200]
I142605 main qe3Gugc type=[HTTP] result=[true] duration=[0.023499] name=[https://letsencrypt.org-200]
I142605 main _J2k0wo type=[HTTP] result=[true] duration=[0.044429] name=[http://letsencrypt.org-200]
I142606 main zomKjwc type=[DNS] result=[false] duration=[0.000017] name=[udp-2606:4700:4700::1111:53-google.com-A]
I142606 main 6parpwM type=[DNS] result=[false] duration=[0.000014] name=[tcp-2606:4700:4700::1111:53-google.com-A]
I142606 main pJqFmAs type=[DNS] result=[true] duration=[0.004667] name=[udp-1.1.1.1:53-google.com-A]
I142606 main 9f7d2AM type=[DNS] result=[true] duration=[0.008965] name=[tcp-1.1.1.1:53-google.com-A]
I142606 main 962rkgM type=[DNS] result=[true] duration=[0.013107] name=[udp-owen.ns.cloudflare.com:53-letsencrypt.org-A]
I142606 main l-r29gc type=[DNS] result=[true] duration=[0.016294] name=[tcp-owen.ns.cloudflare.com:53-letsencrypt.org-A]
I142607 main t_vrtAQ type=[HTTP] result=[true] duration=[0.022378] name=[https://letsencrypt.org-200]
I142607 main v7SjtQM type=[HTTP] result=[true] duration=[0.043780] name=[http://letsencrypt.org-200]
I142609 main ptjWkQM type=[HTTP] result=[true] duration=[0.021068] name=[https://letsencrypt.org-200]
I142609 main jPzToww type=[HTTP] result=[true] duration=[0.042141] name=[http://letsencrypt.org-200]
I142611 main 5IygqAI type=[DNS] result=[false] duration=[0.000019] name=[udp-2606:4700:4700::1111:53-google.com-A]
I142611 main zqe61Qk type=[DNS] result=[false] duration=[0.000012] name=[tcp-2606:4700:4700::1111:53-google.com-A]
I142611 main k9Xh1AU type=[DNS] result=[true] duration=[0.008134] name=[udp-8.8.8.8:53-google.com-A]
I142611 main trL2mwU type=[DNS] result=[true] duration=[0.008801] name=[udp-1.1.1.1:53-google.com-A]
I142611 main _qLDgwk type=[DNS] result=[true] duration=[0.011323] name=[tcp-8.8.8.8:53-google.com-A]
I142611 main rJDj2AI type=[DNS] result=[true] duration=[0.012559] name=[tcp-1.1.1.1:53-google.com-A]
I142611 main teWD6Qs type=[DNS] result=[true] duration=[0.015299] name=[udp-owen.ns.cloudflare.com:53-letsencrypt.org-A]
I142611 main kPrnlg4 type=[DNS] result=[true] duration=[0.019022] name=[tcp-owen.ns.cloudflare.com:53-letsencrypt.org-A]
I142611 main xb_w9gs type=[HTTP] result=[true] duration=[0.025506] name=[https://letsencrypt.org-200]
I142611 main oKi2ggk type=[HTTP] result=[true] duration=[0.074734] name=[http://letsencrypt.org-200]
I142613 main wPqP-gg type=[HTTP] result=[true] duration=[0.021814] name=[https://letsencrypt.org-200]
I142613 main 4IrYoQY type=[HTTP] result=[true] duration=[0.041857] name=[http://letsencrypt.org-200]
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