FROM buildpack-deps:focal-scm as godeps
ARG GO_VERSION
# Provided automatically by docker buildx.
ARG TARGETPLATFORM
ARG BUILDPLATFORM
ENV TARGETPLATFORM=${TARGETPLATFORM:-$BUILDPLATFORM}
ENV GO_VERSION=$GO_VERSION
ENV PATH /usr/local/go/bin:/usr/local/protoc/bin:$PATH
ENV GOBIN /usr/local/bin/
RUN curl "https://dl.google.com/go/go${GO_VERSION}.$(echo $TARGETPLATFORM | sed 's|\/|-|').tar.gz" |\
    tar -C /usr/local -xz
RUN go install github.com/rubenv/sql-migrate/sql-migrate@v1.1.2
RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.28.0
RUN go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.2.0
RUN go install github.com/letsencrypt/pebble/v2/cmd/pebble-challtestsrv@66511d8
RUN go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.53.3
RUN go install honnef.co/go/tools/cmd/staticcheck@2023.1.5

FROM buildpack-deps:focal-scm
COPY requirements.txt /tmp/requirements.txt
COPY boulder.rsyslog.conf /etc/rsyslog.d/
COPY build.sh /tmp/build.sh
RUN /tmp/build.sh

RUN sed -i '/imklog/s/^/#/' /etc/rsyslog.conf
RUN sed -i '/$ActionFileDefaultTemplate/s/^/#/' /etc/rsyslog.conf
RUN sed -i '/$RepeatedMsgReduction on/s/^/#/' /etc/rsyslog.conf

COPY --from=godeps /usr/local/bin/* /usr/local/bin/
COPY --from=godeps /usr/local/go/ /usr/local/go/

ENV PATH /usr/local/go/bin:/usr/local/protoc/bin:$PATH
