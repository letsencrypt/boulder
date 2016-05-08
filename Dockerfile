FROM j4cob/boulder-tools:latest

# Boulder exposes its web application at port TCP 4000
EXPOSE 4000 4002 4003 8053 8055

COPY ./test/docker-environment /etc/environment
ENV BASH_ENV /etc/environment
ENV GO15VENDOREXPERIMENT 1
ENV GOMAXPROCS 2
ENV GOBIN /go/src/github.com/letsencrypt/boulder/bin

RUN adduser --disabled-password --gecos "" -q buser
RUN chown -R buser /go/

WORKDIR /go/src/github.com/letsencrypt/boulder

# Copy in the Boulder sources
COPY . .
RUN mkdir bin
RUN go install ./cmd/rabbitmq-setup
COPY ./test/certbot /go/bin/

RUN chown -R buser /go/

ENTRYPOINT [ "./test/entrypoint.sh" ]
