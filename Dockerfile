# docker build \
#     --build-arg COMMIT_ID=$(git rev-parse --short=8 HEAD) \
#     --build-arg GO_VERSION=1.24.5 \
#     --tag boulder:$(git rev-parse --short=8 HEAD) \
#     .

FROM docker.io/ubuntu:24.04 AS builder

ARG COMMIT_ID
ARG GO_VERSION

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get --assume-yes --no-install-recommends --update install \
    ca-certificates curl gcc git gnupg2 libc6-dev

COPY tools/fetch-and-verify-go.sh /tmp
RUN /tmp/fetch-and-verify-go.sh ${GO_VERSION}
RUN tar -C /usr/local -xzf go.tar.gz

COPY . /boulder
WORKDIR /boulder

ENV GOBIN=/usr/local/bin/
ENV GO111MODULE=on
RUN /usr/local/go/bin/go install \
    -buildvcs=false \
    -ldflags="-X \"github.com/letsencrypt/boulder/core.BuildID=${COMMIT_ID}\" -X \"github.com/letsencrypt/boulder/core.BuildTime=$(date -u)\"" \
    -mod=vendor \
    ./cmd/boulder

FROM docker.io/ubuntu:24.04

COPY --from=builder /usr/local/bin/boulder /usr/local/bin/boulder
