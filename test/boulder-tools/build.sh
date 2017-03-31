#!/bin/bash -ex

# Boulder deps
apt-get update

apt-get install -y --no-install-recommends \
  libltdl-dev \
  mariadb-client-core-10.0 \
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
export GOBIN=/usr/local/bin GOPATH=/tmp/gopath
go get \
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
  golang.org/x/tools/cover \
  golang.org/x/tools/cmd/stringer &

wait

# grpc uses a version attestation variable of the form grpc.SupportPackageIsVersionN
# where N is the minor release version of the protoc-gen-go version used to
# generate the protobuf mappings that are used. Checkout the specific version
# we used to generate the checked in protobuf mappings so that we get the
# same mappings + version number even if protoc-gen-go bumps the minor version
# number
cd $GOPATH/src/github.com/golang/protobuf/protoc-gen-go
git checkout c9c7427a2a70d2eb3bafa0ab2dc163e45f143317
go install ./

git clone https://github.com/certbot/certbot /certbot
cd /certbot
./letsencrypt-auto --os-packages-only
./tools/venv.sh
cd -

# Install pkcs11-proxy. Checked out commit was master HEAD at time
# of writing
git clone https://github.com/SUNET/pkcs11-proxy /tmp/pkcs11-proxy && \
  cd /tmp/pkcs11-proxy && \
  git checkout 944684f78bca0c8da6cabe3fa273fed3db44a890 && \
  cmake . && make && make install && \
  cd - && rm -r /tmp/pkcs11-proxy

# Setup SoftHSM
echo "0:/var/lib/softhsm/slot0.db" > /etc/softhsm/softhsm.conf
echo "1:/var/lib/softhsm/slot1.db" >> /etc/softhsm/softhsm.conf
softhsm --slot 0 --init-token --label intermediate --pin 5678 --so-pin 1234
softhsm --slot 1 --init-token --label root --pin 5678 --so-pin 1234

gem install fpm

# We can't remove libseccomp-dev as it contains a shared object that is required
# for pkcs11-proxy to run properly
apt-get autoremove -y build-essential cmake libssl-dev ruby-dev
apt-get clean -y

rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
