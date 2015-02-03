FROM golang:1.4

MAINTAINER J.C. Jones "jjones@mozilla.com"

# Boulder exposes its web application at port TCP 4000
EXPOSE 4000

# Load the dependencies
RUN go-wrapper download github.com/bifurcation/gose && \
    go-wrapper download github.com/codegangsta/cli && \
    go-wrapper download github.com/streadway/amqp

# Copy in the Boulder sources
RUN mkdir -p /go/src/github.com/letsencrypt/boulder
COPY . /go/src/github.com/letsencrypt/boulder

# Build Boulder
RUN cd /go/src/github.com/letsencrypt/boulder && \
    go build && \
    cd boulder-start && \
    go build

# Simplify run execution
WORKDIR /go/src/github.com/letsencrypt/boulder/boulder-start

# Default run configuration in Monolithic mode without AMQP
CMD ["./boulder-start", "monolithic"]