#!/bin/bash -ex
#
# Install a specific version of Go (provided by the $GO_VERSION variable)
# and then install some dev dependencies using that version of Go.

arch=$(echo $TARGETPLATFORM | sed 's|\/|-|')
curl "https://dl.google.com/go/go${GO_VERSION}.${arch}.tar.gz" | tar -C /usr/local -xz

# Override default GOBIN and GOCACHE
export GOBIN=/usr/local/bin GOCACHE=/tmp/gocache

# Install protobuf and testing/dev tools.
# Note: The version of golang/protobuf is partially tied to the version of grpc
# used by Boulder overall. Updating it may require updating the grpc version
# and vice versa.
go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.28.0
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.2.0
go install github.com/rubenv/sql-migrate/...@v1.1.2
go install golang.org/x/tools/cmd/stringer@latest
go install github.com/letsencrypt/pebble/cmd/pebble-challtestsrv@master
go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.53.3
go install honnef.co/go/tools/cmd/staticcheck@2023.1.5

go clean -cache
go clean -modcache
