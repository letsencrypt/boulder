FROM golang:1.5

MAINTAINER J.C. Jones "jjones@letsencrypt.org"
MAINTAINER William Budington "bill@eff.org"

# Boulder deps
RUN apt-get update && apt-get install -y --no-install-recommends \
  libltdl-dev \
  mariadb-client-core-10.0 \
  nodejs \
  rpm \
  ruby \
  ruby-dev \
  rsyslog \
  softhsm && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

RUN gem install fpm

# Client deps
RUN apt-get update && apt-get install -y --no-install-recommends \
  apache2 \
  ca-certificates \
  gcc \
  libaugeas0 \
  libffi-dev \
  libssl-dev \
  nginx-light \
  openssl \
  python-dev \
  python-virtualenv \
  virtualenv \
  && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Install port forwarder, database migration tool, and testing tools.
RUN GOBIN=/usr/local/bin GOPATH=/tmp/gopath go get \
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
  golang.org/x/tools/cover && rm -rf /tmp/gopath

# Install protoc (used for testing that generated code is up-to-date)
RUN curl -sL https://github.com/google/protobuf/releases/download/v2.6.1/protobuf-2.6.1.tar.gz | \
 tar -xz && cd protobuf-2.6.1 && ./configure && make install > /dev/null && \
 cd .. && rm  -rf protobuf-2.6.1{,.tar.gz}

# Boulder exposes its web application at port TCP 4000
EXPOSE 4000 4002 4003 8053 8055

COPY ./test/docker-environment /etc/environment
ENV BASH_ENV /etc/environment
ENV GO15VENDOREXPERIMENT 1
ENV GOBIN /go/src/github.com/letsencrypt/boulder/bin

RUN adduser --disabled-password --gecos "" -q buser
RUN chown -R buser /go/

WORKDIR /go/src/github.com/letsencrypt/boulder

# Copy in the Boulder sources
COPY . .
RUN mkdir bin
RUN go install ./...

RUN chown -R buser /go/

ENTRYPOINT [ "./test/entrypoint.sh" ]
