#!/usr/bin/env bash
#
# Applies transformations to source trees to keep up to date with
# with the external API.
#
if [ -z "$@" ]; then
  echo "Usage: $0 path/to/package"
  exit 1
fi

gofmt \
  -r 'NewStatsd(a) -> Dial("udp",a)' \
  -r 'UpdateGague(a,b) -> Gauge(1.0,a,b)' \
  -r 'UpdateSampledGaguge(a,b,c) -> Gauge(c,a,b)' \
  -r 'SendTiming(a,b) -> Timing(1.0,a,b)' \
  -r 'SendSampledTiming(a,b,c) -> Timing(c,a,b)' \
  -r 'IncrementCounter(a,b) -> Count(1.0,a,b)' \
  -r 'IncrementSampledCounter(a,b,c) -> Count(c,a,b)' \
  -w $@
