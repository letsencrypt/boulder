FROM golang:1.4

MAINTAINER J.C. Jones "jjones@mozilla.com"

# Boulder exposes its web application at port TCP 4000
EXPOSE 4000

# Load the dependencies
RUN go-wrapper download github.com/bifurcation/gose && \
    go-wrapper download github.com/codegangsta/cli && \
    go-wrapper download github.com/streadway/amqp && \
    go-wrapper download github.com/mattn/go-sqlite3 && \
    go-wrapper download github.com/cloudflare/cfssl/auth && \
    go-wrapper download github.com/cloudflare/cfssl/config && \
    go-wrapper download github.com/cloudflare/cfssl/signer

# Copy in the Boulder sources
RUN mkdir -p /go/src/github.com/letsencrypt/boulder
COPY . /go/src/github.com/letsencrypt/boulder

# Build Boulder
RUN go install github.com/letsencrypt/boulder/cmd/boulder-start

ENTRYPOINT ["/go/bin/boulder-start"]
