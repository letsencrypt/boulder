# eggsampler/acme

[![GoDoc](https://godoc.org/github.com/eggsampler/acme?status.svg)](https://godoc.org/github.com/eggsampler/acme)
[![Build Status](https://travis-ci.com/eggsampler/acme.svg?branch=master)](https://travis-ci.com/eggsampler/acme)
[![Coverage Status](https://coveralls.io/repos/github/eggsampler/acme/badge.svg?branch=master)](https://coveralls.io/github/eggsampler/acme?branch=master)

## About

`eggsampler/acme` is a Go client library implementation for [RFC8555](https://tools.ietf.org/html/rfc8555) (previously ACME v2), specifically for use with the [Let's Encrypt](https://letsencrypt.org/)™ service. 

The library is designed to provide a zero external dependency wrapper over exposed directory endpoints and provide objects in easy to use structures.

## Requirements

A Go version of at least 1.11 is required as this repository is designed to be imported as a Go module.

## Usage

Simply import the module into a project,

```go
import "github.com/eggsampler/acme/v3"
```

Note the `/v3` major version at the end. Due to the way modules function, this is the major version as represented in the `go.mod` file and latest git repo [semver](https://semver.org/) tag.
All functions are still exported and called using the `acme` package name.

## Examples

A simple [certbot](https://certbot.eff.org/)-like example is provided in the examples/certbot directory.
This code demonstrates account registration, new order submission, fulfilling challenges, finalising an order and fetching the issued certificate chain.

An example of how to use the autocert package is also provided in examples/autocert.

## Tests

The tests can be run against an instance of [boulder](https://github.com/letsencrypt/boulder) or [pebble](https://github.com/letsencrypt/pebble).

Challenge fulfilment is designed to use the new `challtestsrv` server present inside boulder and pebble which responds to dns queries and challenges as required.

To run tests against an already running instance of boulder or pebble, use the `test` target in the Makefile.

Some convenience targets for launching pebble/boulder using their respective docker compose files have also been included in the Makefile.
