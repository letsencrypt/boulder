#!/bin/bash -ex

apt-get update

# Install system deps
apt-get install -y --no-install-recommends \
  mariadb-client-core-10.1 \
  rpm \
  ruby \
  ruby-dev \
  rsyslog \
  softhsm \
  build-essential \
  cmake \
  libssl-dev \
  libseccomp-dev \
  opensc \
  unzip \
  python3-pip \
  python3-acme \
  gcc \
  ca-certificates \
  openssl

curl -L https://github.com/google/protobuf/releases/download/v3.6.1/protoc-3.6.1-linux-x86_64.zip -o /tmp/protoc.zip
unzip /tmp/protoc.zip -d /usr/local/protoc

# Override default GOBIN and GOPATH
export GOBIN=/usr/local/bin GOPATH=/tmp/gopath

# Install protobuf and testing/dev tools.
go get \
  github.com/letsencrypt/pebble/cmd/pebble-challtestsrv \
  bitbucket.org/liamstask/goose/cmd/goose \
  golang.org/x/lint/golint \
  github.com/golang/mock/mockgen \
  github.com/golang/protobuf/proto \
  github.com/golang/protobuf/protoc-gen-go \
  github.com/kisielk/errcheck \
  github.com/mattn/goveralls \
  github.com/modocache/gover \
  golang.org/x/tools/cover \
  golang.org/x/tools/cmd/stringer \
  github.com/gordonklaus/ineffassign

go clean -cache
go clean -modcache

# Install codespell for linting common spelling errors
pip3 install -r /tmp/requirements.txt

# Install pkcs11-proxy. Checked out commit was master HEAD at time
# of writing
git clone https://github.com/SUNET/pkcs11-proxy /tmp/pkcs11-proxy && \
  cd /tmp/pkcs11-proxy && \
  git checkout 944684f78bca0c8da6cabe3fa273fed3db44a890 && \
  cmake . && make && make install && \
  cd - && rm -r /tmp/pkcs11-proxy

# Setup SoftHSM
echo "directories.tokendir = /var/lib/softhsm/tokens/" > /etc/softhsm/softhsm2.conf
mkdir -p /var/lib/softhsm/tokens
softhsm2-util --slot 0 --init-token --label intermediate --pin 5678 --so-pin 1234
softhsm2-util --slot 1 --init-token --label root --pin 5678 --so-pin 1234

gem install fpm

# We can't remove libseccomp-dev as it contains a shared object that is required
# for pkcs11-proxy to run properly
apt-get autoremove -y libssl-dev ruby-dev build-essential cmake
apt-get clean -y

rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
