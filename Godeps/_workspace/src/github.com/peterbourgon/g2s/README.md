# g2s

Get to Statsd: forward simple statistics to a statsd server.

[![Build Status][1]][2] [![GoDoc][3]][4]

[1]: https://secure.travis-ci.org/peterbourgon/g2s.png
[2]: http://www.travis-ci.org/peterbourgon/g2s
[3]: https://godoc.org/github.com/peterbourgon/g2s?status.svg
[4]: https://godoc.org/github.com/peterbourgon/g2s

# Usage

g2s provides a Statsd object, which provides some convenience functions for
each of the supported statsd statistic-types. Just call the relevant function
on the Statsd object wherever it makes sense in your code.

```go
s, err := g2s.Dial("udp", "statsd-server:8125")
if err != nil {
	// do something
}

s.Counter(1.0, "my.silly.counter", 1)
s.Timing(1.0, "my.silly.slow-process", time.Since(somethingBegan))
s.Timing(0.2, "my.silly.fast-process", 7*time.Millisecond)
s.Gauge(1.0, "my.silly.status", "green")
```

If you use a standard UDP connection to a statsd server, all 'update'-class
functions are goroutine safe. They should return quickly, but they're safe to
fire in a seperate goroutine.

# Upgrading API

Upgrade to the latest API by running `./fix.bash *.go` where `*.go` expands to
the paths of the source files you'd like to rewrite to the new API.
