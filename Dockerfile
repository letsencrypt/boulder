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
