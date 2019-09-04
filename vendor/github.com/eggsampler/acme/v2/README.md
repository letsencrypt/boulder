# eggsampler/acme

[![GoDoc](https://godoc.org/github.com/eggsampler/acme?status.svg)](https://godoc.org/github.com/eggsampler/acme) [![Build Status](https://travis-ci.com/eggsampler/acme.svg?branch=master)](https://travis-ci.com/eggsampler/acme) [![codecov.io](https://codecov.io/gh/eggsampler/acme/branch/master/graph/badge.svg)](https://codecov.io/gh/eggsampler/acme/branch/master)

## About

`eggsampler/acme` is a Go client library implementation for [RFC8555](https://tools.ietf.org/html/rfc8555) (previously ACME), specifically for use with the [Let's Encrypt](https://letsencrypt.org/) service. 

The library is designed to provide a zero external dependency wrapper over exposed directory endpoints and provide objects in easy to use structures.

## Example

A simple [certbot](https://certbot.eff.org/)-like example is provided in the examples/certbot directory. This code demonstrates account registration, new order submission, fulfilling challenges, finalising an order and fetching the issued certificate chain.

An example of how to use the autocert package is also provided in examples/autocert.

## Tests

The tests can be run against an instance of [boulder](https://github.com/letsencrypt/boulder) or [pebble](https://github.com/letsencrypt/pebble).

Challenge fulfilment is designed to use the new `challtestsrv` server present inside boulder and pebble which responds to dns queries and challenges as required.

To run tests against an already running instance of boulder or pebble, use the `test` target in the Makefile.

Some convenience targets for launching pebble/boulder using their respective docker compose files have also been included in the Makefile.
