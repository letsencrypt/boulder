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

# protoc-gen-go outputs a line that says:
# const _ = grpc.SupportPackageIsVersion4
# so it will fail to compile with a different version of the grpc package.
# Since we currently have version 3 of the grpc package vendored, we have to
# build a specific version of protoc-gen-go.
cd $GOPATH/src/github.com/golang/protobuf/protoc-gen-go
git checkout 78b168c14fc28c8c711844d210f7ab845083e3b1
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
