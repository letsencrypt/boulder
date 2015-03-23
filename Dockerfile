FROM golang:1.4.2

MAINTAINER J.C. Jones "jjones@letsencrypt.org"

# Boulder exposes its web application at port TCP 4000
EXPOSE 4000

# Assume the configuration is in /etc/boulder
ENV BOULDER_CONFIG=/boulder/config.json

# Load the dependencies
RUN go-wrapper download github.com/bifurcation/gose && \
    go-wrapper download github.com/codegangsta/cli && \
    go-wrapper download github.com/streadway/amqp && \
    go-wrapper download github.com/mattn/go-sqlite3 && \
    go-wrapper download github.com/go-sql-driver/mysql && \
    go-wrapper download github.com/cloudflare/cfssl/auth && \
    go-wrapper download github.com/cloudflare/cfssl/config && \
    go-wrapper download github.com/cloudflare/cfssl/signer

# Copy in the Boulder sources
RUN mkdir -p /go/src/github.com/letsencrypt/boulder
COPY . /go/src/github.com/letsencrypt/boulder

# Build Boulder
RUN go install \
  github.com/letsencrypt/boulder/cmd/activity-monitor \
  github.com/letsencrypt/boulder/cmd/boulder \
  github.com/letsencrypt/boulder/cmd/boulder-ca \
  github.com/letsencrypt/boulder/cmd/boulder-ra \
  github.com/letsencrypt/boulder/cmd/boulder-sa \
  github.com/letsencrypt/boulder/cmd/boulder-va \
  github.com/letsencrypt/boulder/cmd/boulder-wfe

CMD ["/go/bin/boulder"]
