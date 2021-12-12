FROM buildpack-deps:focal-scm

RUN apt-get update
# Install system deps
RUN apt-get install -y --no-install-recommends \
  mariadb-client-core-10.3 \
  rpm \
  ruby \
  ruby-dev \
  rsyslog \
  build-essential \
  cmake \
  libssl-dev \
  opensc \
  unzip \
  python3-pip \
  gcc \
  ca-certificates \
  openssl \
  softhsm2 \
  pkg-config \
  libtool \
  autoconf \
  automake

ARG GO_VERSION
# Provided automatically by docker buildx.
ARG TARGETPLATFORM
ARG BUILDPLATFORM

# Copied from https://github.com/docker-library/golang/blob/master/Dockerfile-debian.template
ENV GOPATH /go
ENV GOARCH=$TARGETARCH
ENV PATH $GOPATH/bin:/usr/local/go/bin:/usr/local/protoc/bin:$PATH
RUN mkdir -p "$GOPATH/src" "$GOPATH/bin" && chmod -R 777 "$GOPATH"
WORKDIR $GOPATH

RUN arch=$(echo $TARGETPLATFORM | sed 's|\/|-|') && wget -O go.tgz "https://dl.google.com/go/go${GO_VERSION}.${arch}.tar.gz" && tar -C /usr/local -xzf go.tgz && rm go.tgz;
COPY requirements.txt /tmp/requirements.txt
COPY boulder.rsyslog.conf /etc/rsyslog.d/
COPY build.sh /tmp/build.sh
RUN /tmp/build.sh
RUN sed -i '/$ActionFileDefaultTemplate/s/^/#/' /etc/rsyslog.conf
RUN sed -i '/imklog/s/^/#/' /etc/rsyslog.conf
