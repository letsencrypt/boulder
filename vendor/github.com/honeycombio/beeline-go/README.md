# Honeycomb Beeline for Go

[![CircleCI](https://circleci.com/gh/honeycombio/beeline-go.svg?style=shield)](https://circleci.com/gh/honeycombio/beeline-go)
[![GoDoc](https://godoc.org/github.com/honeycombio/beeline-go?status.svg)](https://godoc.org/github.com/honeycombio/beeline-go)

This package makes it easy to instrument your Go app to send useful events to [Honeycomb](https://www.honeycomb.io), a service for debugging your software in production.
- [Usage and Examples](https://docs.honeycomb.io/getting-data-in/beelines/go-beeline/)
- [API Reference](https://godoc.org/github.com/honeycombio/beeline-go)
  - For each [wrapper](wrappers/), please see the [godoc](https://godoc.org/github.com/honeycombio/beeline-go#pkg-subdirectories)

## Dependencies

The beeline uses [go modules](https://golang.org/cmd/go/#hdr-Modules__module_versions__and_more) to track external dependencies: golang 1.11 or newer is therefore required to build

## Contributions

Features, bug fixes and other changes to `beeline-go` are gladly accepted. Please
open issues or a pull request with your change. Remember to add your name to the
CONTRIBUTORS file!

All contributions will be released under the Apache License 2.0.
