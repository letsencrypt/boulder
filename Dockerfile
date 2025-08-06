# This builds Boulder in a Docker container, then creates an image
# containing just the built Boulder binaries plus some ancillary
# files that are useful for predeployment testing.
FROM docker.io/ubuntu:24.04 AS builder

ARG COMMIT_ID
ARG GO_VERSION

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get --assume-yes --no-install-recommends --update install \
    ca-certificates curl gcc git gnupg2 libc6-dev

COPY tools/fetch-and-verify-go.sh /tmp
RUN /tmp/fetch-and-verify-go.sh ${GO_VERSION}
RUN tar -C /opt -xzf go.tar.gz

COPY . /opt/boulder
WORKDIR /opt/boulder

ENV GO111MODULE=on
ENV GOBIN=/opt/boulder/bin/
RUN /opt/go/bin/go install \
    -buildvcs=false \
    -ldflags="-X \"github.com/letsencrypt/boulder/core.BuildID=${COMMIT_ID}\" -X \"github.com/letsencrypt/boulder/core.BuildTime=$(date -u)\"" \
    -mod=vendor \
    ./...

FROM docker.io/ubuntu:24.04

LABEL org.opencontainers.image.authors="Internet Security Research Group, https://letsencrypt.org/"
LABEL org.opencontainers.image.created="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
LABEL org.opencontainers.image.description="Boulder is an ACME-compatible X.509 Certificate Authority"
LABEL org.opencontainers.image.documentation="https://github.com/letsencrypt/boulder"
LABEL org.opencontainers.image.licenses="MPL-2.0"
LABEL org.opencontainers.image.source="https://github.com/letsencrypt/boulder"
LABEL org.opencontainers.image.title="Boulder"
LABEL org.opencontainers.image.url="https://github.com/letsencrypt/boulder"
LABEL org.opencontainers.image.vendor="Internet Security Research Group"
#LABEL org.opencontainers.image.version="${GO_VERSION}.$(date +%s)"

COPY --from=builder \
    /opt/boulder/bin/admin /opt/boulder/bin/boulder /opt/boulder/bin/chall-test-srv /opt/boulder/bin/ct-test-srv /opt/boulder/bin/pardot-test-srv \
    /opt/boulder/bin/
COPY --from=builder /opt/boulder/data /opt/boulder/data
COPY --from=builder /opt/boulder/sa/db /opt/boulder/sa/db
COPY --from=builder /opt/boulder/test/config /opt/boulder/test/config
