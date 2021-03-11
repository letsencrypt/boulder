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
  pkg-config \
  libtool \
  autoconf \
  automake

curl -L https://github.com/google/protobuf/releases/download/v3.11.4/protoc-3.11.4-linux-x86_64.zip -o /tmp/protoc.zip
unzip /tmp/protoc.zip -d /usr/local/protoc

# Override default GOBIN and GOCACHE
export GOBIN=/usr/local/bin GOCACHE=/tmp/gocache

# Install golangci-lint
curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $GOBIN v1.29.0

# Install protobuf and testing/dev tools.
# Note: The version of golang/protobuf is partially tied to the version of grpc
# used by Boulder overall. Updating it may require updating the grpc version
# and vice versa.
GO111MODULE=on go get \
  bitbucket.org/liamstask/goose/cmd/goose \
  github.com/golang/mock/mockgen@v1.3.0 \
  github.com/golang/protobuf/proto@v1.4.0 \
  github.com/golang/protobuf/protoc-gen-go@v1.4.0 \
  github.com/mattn/goveralls@v0.0.3 \
  github.com/modocache/gover \
  golang.org/x/tools/cover \
  golang.org/x/tools/cmd/stringer

# Pebble's latest version is v2+, but it's not properly go mod compatible, so we
# fetch it in GOPATH mode.
GO111MODULE=off go get github.com/letsencrypt/pebble/cmd/pebble-challtestsrv

go clean -cache
go clean -modcache

pip3 install -r /tmp/requirements.txt

# Install a newer version (2.5.0) of SoftHSM2 than is available from the debian
# repository
git clone https://github.com/opendnssec/SoftHSMv2.git /tmp/softhsm2 --branch 2.5.0 --depth 1
cd /tmp/softhsm2
sh autogen.sh
./configure --disable-gost
make && make install
cd - && rm -r /tmp/softhsm2

# Setup SoftHSM
mkdir -p /etc/softhsm
echo "directories.tokendir = /var/lib/softhsm/tokens/" > /etc/softhsm/softhsm2.conf
mkdir -p /var/lib/softhsm/tokens

gem install --no-document fpm

apt-get autoremove -y libssl-dev ruby-dev cmake pkg-config libtool autoconf automake
apt-get clean -y

rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
