#!/bin/bash -ex

# Boulder deps
apt-get update
apt-get install -y --no-install-recommends apt-transport-https ca-certificates

curl -s https://deb.nodesource.com/gpgkey/nodesource.gpg.key | apt-key add -
cat >/etc/apt/sources.list.d/bouldertools.list <<EOAPT
deb https://deb.nodesource.com/node_4.x trusty main
deb-src https://deb.nodesource.com/node_4.x trusty main
deb http://ftp.debian.org/debian jessie-backports main
EOAPT
apt-get update
apt-get install -y --no-install-recommends  -t jessie-backports certbot python-certbot python-certbot-apache python-cffi

apt-get install -y --no-install-recommends \
  libltdl-dev \
  mariadb-client-core-10.0 \
  nodejs \
  rpm \
  ruby \
  ruby-dev \
  rsyslog \
  protobuf-compiler \
  softhsm \
  build-essential \
  cmake \
  libssl-dev \
  libseccomp-dev \
  opensc &

# Install port forwarder, database migration tool, and testing tools.
GOBIN=/usr/local/bin GOPATH=/tmp/gopath go get \
  github.com/jsha/listenbuddy \
  bitbucket.org/liamstask/goose/cmd/goose \
  github.com/golang/lint/golint \
  github.com/golang/mock/mockgen \
  github.com/golang/protobuf/proto \
  github.com/golang/protobuf/protoc-gen-go \
  github.com/kisielk/errcheck \
  github.com/mattn/goveralls \
  github.com/modocache/gover \
  github.com/tools/godep \
  golang.org/x/tools/cover &

wait

# Install pkcs11-proxy. Checked out commit was master HEAD at time
# of writing
git clone https://github.com/SUNET/pkcs11-proxy && \
  cd pkcs11-proxy && \
  git checkout 944684f78bca0c8da6cabe3fa273fed3db44a890 && \
  cmake . && make && make install && \
  cd -

# Setup SoftHSM
echo "0:/var/lib/softhsm/slot0.db" > /etc/softhsm/softhsm.conf
pkcs11-tool --module=/usr/lib/softhsm/libsofthsm.so --init-token --label token_label --so-pin 1234
pkcs11-tool --module=/usr/lib/softhsm/libsofthsm.so --init-pin --label token_label --pin 5678 --login --so-pin 1234

gem install fpm

# We can't remove libseccomp-dev as it contains a shared object that is required
# for pkcs11-proxy to run properly
apt-get autoremove -y build-essential cmake libssl-dev
apt-get clean -y

rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
