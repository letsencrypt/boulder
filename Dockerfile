FROM letsencrypt/boulder-tools:latest

# Boulder exposes its web application at port TCP 4000
EXPOSE 4000 4002 4003 8053 8055

ENV GO15VENDOREXPERIMENT 1
ENV GOBIN /go/src/github.com/letsencrypt/boulder/bin
ENV PATH /go/bin:/go/src/github.com/letsencrypt/boulder/bin:/usr/local/go/bin:/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin/
ENV GOPATH /go

RUN adduser --disabled-password --gecos "" --home /go/src/github.com/letsencrypt/boulder -q buser
RUN chown -R buser /go/

WORKDIR /go/src/github.com/letsencrypt/boulder

# Copy in the Boulder sources
COPY . .
RUN mkdir bin
RUN go install ./cmd/rabbitmq-setup
COPY ./test/certbot /go/bin/

RUN chown -R buser /go/

ENTRYPOINT [ "./test/entrypoint.sh" ]
