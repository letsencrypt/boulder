FROM golang:1.5

MAINTAINER J.C. Jones "jjones@letsencrypt.org"
MAINTAINER William Budington "bill@eff.org"

# Install dependencies packages
RUN apt-get update && apt-get install -y \
	libltdl-dev \
	mariadb-client-core-10.0 \
	nodejs \
	rsyslog \
	softhsm \
	--no-install-recommends \
	&& rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Install port forwarder, database migration tool and go lint
RUN go get -v \
	github.com/jsha/listenbuddy \
	bitbucket.org/liamstask/goose/cmd/goose \
	github.com/golang/lint/golint

# Boulder exposes its web application at port TCP 4000
EXPOSE 4000 4002 4003

ENV GOPATH /go/src/github.com/letsencrypt/boulder/Godeps/_workspace:$GOPATH

WORKDIR /go/src/github.com/letsencrypt/boulder

ENTRYPOINT [ "./test/entrypoint.sh" ]

# Copy in the Boulder sources
COPY . /go/src/github.com/letsencrypt/boulder

RUN GOBIN=/go/src/github.com/letsencrypt/boulder/bin go install  ./...
