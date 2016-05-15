FROM j4cob/boulder-tools:latest

# Boulder exposes its web application at port TCP 4000
EXPOSE 4000 4002 4003 8053 8055

COPY ./test/docker-environment /etc/environment
ENV BASH_ENV /etc/environment
ENV GO15VENDOREXPERIMENT 1
ENV GOBIN /go/src/github.com/letsencrypt/boulder/bin
ENV CERTBOT_PATH /certbot
# This is observed by certbot's tools/venv.sh and test.sh, and allows a
# Dockerized virtualenv to exist alongside a regular virtualenv.
ENV VENV_NAME dvenv

RUN adduser --disabled-password --gecos "" --home /go/src/github.com/letsencrypt/boulder -q buser
RUN chown -R buser /go/

WORKDIR /go/src/github.com/letsencrypt/boulder

# Copy in the Boulder sources
COPY . .
RUN mkdir bin
RUN go install ./cmd/rabbitmq-setup

RUN chown -R buser /go/

ENTRYPOINT [ "./test/entrypoint.sh" ]
