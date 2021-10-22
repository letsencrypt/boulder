#!/bin/bash -ex

apt-get update

# Install system deps
apt-get install -y --no-install-recommends \
  mariadb-client-core-10.3 \
  rpm \
  ruby \
  ruby-dev \
  rsyslog \
  build-essential \
  cmake \
  libssl-dev \
  opensc \
  unzip \
  python3-pip \
  gcc \
  ca-certificates \
  openssl \
  softhsm2 \
  pkg-config \
  libtool \
  autoconf \
  automake

curl -L https://github.com/google/protobuf/releases/download/v3.15.6/protoc-3.15.6-linux-x86_64.zip -o /tmp/protoc.zip
unzip /tmp/protoc.zip -d /usr/local/protoc

# Override default GOBIN and GOCACHE
export GOBIN=/usr/local/bin GOCACHE=/tmp/gocache

# Install golangci-lint
curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $GOBIN v1.42.1

# Install protobuf and testing/dev tools.
# Note: The version of golang/protobuf is partially tied to the version of grpc
# used by Boulder overall. Updating it may require updating the grpc version
# and vice versa.
GO111MODULE=on go get \
  bitbucket.org/liamstask/goose/cmd/goose \
  google.golang.org/protobuf/cmd/protoc-gen-go@v1.26.0 \
  google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.1.0 \
  golang.org/x/tools/cmd/stringer

# Pebble's latest version is v2+, but it's not properly go mod compatible, so we
# fetch it in GOPATH mode.
GO111MODULE=off go get github.com/letsencrypt/pebble/cmd/pebble-challtestsrv

go clean -cache
go clean -modcache

pip3 install -r /tmp/requirements.txt

gem install --no-document fpm

apt-get autoremove -y libssl-dev ruby-dev cmake pkg-config libtool autoconf automake
apt-get clean -y

rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
