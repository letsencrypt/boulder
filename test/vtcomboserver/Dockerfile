# syntax=docker/dockerfile:1
ARG VITESS_TAG=v23.0.0
ARG MYSQL_BASE_IMAGE=mysql:8.4

FROM golang:1.25.2-bookworm AS build
ARG VITESS_TAG
ENV CGO_ENABLED=0

# Largely cobbled together from Vitess's own Dockerfiles and install scripts:
#   - https://github.com/vitessio/vitess/blob/v22.0.1/docker/lite/Dockerfile
#   - https://github.com/vitessio/vitess/blob/v22.0.1/docker/lite/Dockerfile.mysql84
#   - https://github.com/vitessio/vitess/blob/v22.0.1/docker/utils/install_dependencies.sh
#   - https://github.com/vitessio/vitess/blob/v22.0.1/docker/vttestserver/Dockerfile.mysql80

ENV VTROOT=/vt
WORKDIR /src

RUN apt-get update && apt-get install -y --no-install-recommends \
      git ca-certificates \
  && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 --branch "${VITESS_TAG}" https://github.com/vitessio/vitess.git .

# Build only the binaries we need
RUN go build -trimpath -o /out/vtcombo ./go/cmd/vtcombo
RUN go build -trimpath -o /out/mysqlctl ./go/cmd/mysqlctl

FROM ${MYSQL_BASE_IMAGE} AS runtime

# Vitess expects to run as a non-root user
RUN groupadd -r vitess && useradd -r -g vitess vitess

ENV VTROOT=/vt \
    VTDATAROOT=/vt/vtdataroot \
    PATH=/vt/bin:$PATH

WORKDIR /vt

RUN mkdir -p /vt/vtdataroot /vt/bin /vt/config/mycnf /vt/web \
 && chown -R vitess:vitess /vt

# Copy only the binaries we need
COPY --from=build /out/vtcombo  /vt/bin/vtcombo
COPY --from=build /out/mysqlctl /vt/bin/mysqlctl
RUN chmod +x /vt/bin/* && chown -R vitess:vitess /vt/bin

# Copy other necessary files
COPY --from=build --chown=vitess:vitess /src/config/init_db.sql /vt/config/
COPY --from=build --chown=vitess:vitess /src/config/mycnf /vt/config/mycnf
COPY --from=build --chown=vitess:vitess /src/web/vtadmin /vt/web/vtadmin

# Copy install script we use to trigger failures in our integration tests
COPY --chown=vitess:vitess install_trigger.sh /vt/install_trigger.sh
RUN chmod +x /vt/install_trigger.sh

VOLUME /vt/vtdataroot

COPY setup_vschema_folder.sh /vt/setup_vschema_folder.sh
COPY run.sh /vt/run.sh
RUN chmod +x /vt/setup_vschema_folder.sh /vt/run.sh \
 && chown vitess:vitess /vt/setup_vschema_folder.sh /vt/run.sh

USER vitess

CMD ["/vt/run.sh", "8.0.40-Vitess"]
