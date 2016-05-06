#!/bin/bash -ex

# Boulder deps
apt-get update
apt-get install -y --no-install-recommends \
  apt-transport-https \
  libltdl-dev \
  mariadb-client-core-10.0 \
  rpm \
  ruby \
  ruby-dev \
  rsyslog \
  softhsm \
  python-dev \
  python-virtualenv \
  gcc \
  libaugeas0 \
  libssl-dev \
  libffi-dev \
  ca-certificates

curl -s https://deb.nodesource.com/gpgkey/nodesource.gpg.key | apt-key add -
tee /etc/apt/sources.list.d/nodesource.list <<EOAPT
deb https://deb.nodesource.com/node_4.x trusty main
deb-src https://deb.nodesource.com/node_4.x trusty main
EOAPT
apt-get update
apt-get install -y --no-install-recommends nodejs

gem install fpm

# Install port forwarder, database migration tool, and testing tools.
GOBIN=/usr/local/bin GOPATH=/tmp/gopath go get \
  github.com/jsha/listenbuddy \
  bitbucket.org/liamstask/goose/cmd/goose \
  github.com/golang/lint/golint \
  github.com/golang/mock/mockgen \
  github.com/golang/protobuf/proto \
  github.com/golang/protobuf/protoc-gen-go \
  github.com/jcjones/github-pr-status \
  github.com/kisielk/errcheck \
  github.com/mattn/goveralls \
  github.com/modocache/gover \
  github.com/tools/godep \
  golang.org/x/tools/cmd/stringer \
  golang.org/x/tools/cover

# Install protoc (used for testing that generated code is up-to-date)
curl -sL https://github.com/google/protobuf/releases/download/v2.6.1/protobuf-2.6.1.tar.gz | \
 tar -xzC /tmp
(cd /tmp/protobuf-2.6.1 && ./configure && make install)

rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
