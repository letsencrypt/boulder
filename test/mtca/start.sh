#!/usr/bin/env bash

set -feuxo pipefail

make GO=gotip GO_BUILD_FLAGS=
exec ./bin/boulder boulder-mtca -config test/config-next/mtca.json -addr :9396 "$@"
