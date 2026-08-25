ARG SUNLIGHT_TAG=v0.9.0

FROM golang:1.25.2-bookworm AS build
ARG SUNLIGHT_TAG
RUN CGO_ENABLED=1 go install filippo.io/sunlight/cmd/sunlight@${SUNLIGHT_TAG}

FROM debian:bookworm-slim
RUN apt-get update && \
    apt-get install -y --no-install-recommends sqlite3 && \
    rm -rf /var/lib/apt/lists/*
COPY --from=build /go/bin/sunlight /usr/local/bin/sunlight
ENTRYPOINT ["/boulder/test/sunlight/entrypoint.sh"]
