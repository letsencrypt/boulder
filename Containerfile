# This builds Boulder in a Docker container, then creates an image
# containing just the built Boulder binaries plus some ancillary
# files that are useful for predeployment testing.
FROM docker.io/ubuntu:24.04 AS builder

ARG COMMIT_ID
ARG COMMIT_TIMESTAMP
ARG GO_VERSION
ARG VERSION

ENV DEBIAN_FRONTEND=noninteractive
ENV SOURCE_DATE_EPOCH=${COMMIT_TIMESTAMP}
RUN apt-get --assume-yes --no-install-recommends --update install \
    ca-certificates curl gcc git gnupg2 libc6-dev

COPY tools/fetch-and-verify-go.sh /tmp
RUN /tmp/fetch-and-verify-go.sh ${GO_VERSION}
RUN tar -C /opt -xzf go.tar.gz
ENV PATH="/opt/go/bin:${PATH}"

COPY . /opt/boulder
WORKDIR /opt/boulder

ENV GOBIN=/opt/boulder/bin/
RUN go install \
    -buildvcs=false \
    -trimpath \
    -ldflags="-X \"github.com/letsencrypt/boulder/core.BuildID=${COMMIT_ID}\" -X \"github.com/letsencrypt/boulder/core.BuildTime=$(date -u -d @${COMMIT_TIMESTAMP})\"" \
    -mod=vendor \
    ./...

FROM docker.io/ubuntu:24.04

ARG COMMIT_DATE_ISO8601
ARG VERSION

LABEL org.opencontainers.image.authors="Internet Security Research Group, https://letsencrypt.org/"
LABEL org.opencontainers.image.created="${COMMIT_DATE_ISO8601}"
LABEL org.opencontainers.image.description="Boulder is an ACME-compatible X.509 Certificate Authority"
LABEL org.opencontainers.image.documentation="https://github.com/letsencrypt/boulder"
LABEL org.opencontainers.image.licenses="MPL-2.0"
LABEL org.opencontainers.image.source="https://github.com/letsencrypt/boulder"
LABEL org.opencontainers.image.title="Boulder"
LABEL org.opencontainers.image.url="https://github.com/letsencrypt/boulder"
LABEL org.opencontainers.image.vendor="Internet Security Research Group"
LABEL org.opencontainers.image.version="${VERSION}"

COPY --from=builder \
    /opt/boulder/bin/admin \
    /opt/boulder/bin/boulder \
    /opt/boulder/bin/chall-test-srv \
    /opt/boulder/bin/ct-test-srv \
    /opt/boulder/bin/pardot-test-srv \
    /opt/boulder/bin/zendesk-test-srv \
    /opt/boulder/bin/
COPY --from=builder /opt/boulder/data /opt/boulder/data
COPY --from=builder /opt/boulder/sa/db /opt/boulder/sa/db
COPY --from=builder /opt/boulder/test/config /opt/boulder/test/config

ENV PATH="/opt/boulder/bin:${PATH}"
