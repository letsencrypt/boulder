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

PROTO_ARCH=x86_64
if [ "${TARGETPLATFORM}" = linux/arm64 ]
then
  PROTO_ARCH=aarch_64
fi

curl -L https://github.com/google/protobuf/releases/download/v3.15.6/protoc-3.15.6-linux-"${PROTO_ARCH}".zip -o /tmp/protoc.zip
unzip /tmp/protoc.zip -d /usr/local/protoc

# Override default GOBIN and GOCACHE
export GOBIN=/usr/local/bin GOCACHE=/tmp/gocache

# Install golangci-lint
curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $GOBIN v1.42.1

# Install protobuf and testing/dev tools.
# Note: The version of golang/protobuf is partially tied to the version of grpc
# used by Boulder overall. Updating it may require updating the grpc version
# and vice versa.
go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.26.0
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.1.0
go install bitbucket.org/liamstask/goose/cmd/goose@latest
go install golang.org/x/tools/cmd/stringer@latest
go install github.com/letsencrypt/pebble/cmd/pebble-challtestsrv@master

go clean -cache
go clean -modcache

pip3 install -r /tmp/requirements.txt

gem install --no-document -v 1.14.0 fpm

apt-get autoremove -y libssl-dev ruby-dev cmake pkg-config libtool autoconf automake
apt-get clean -y

rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
