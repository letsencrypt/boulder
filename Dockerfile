FROM golang:1.4.2

MAINTAINER J.C. Jones "jjones@letsencrypt.org"
MAINTAINER William Budington "bill@eff.org"

# Install dependencies packages
RUN apt-get update && \
  apt-get install -y --no-install-recommends \
    libltdl-dev \
    rsyslog && \
  apt-get clean && \
  rm -rf /var/lib/apt/lists/* \
    /tmp/* \
    /var/tmp/*

# Boulder exposes its web application at port TCP 4000
EXPOSE 4000

# Assume the configuration is in /etc/boulder
ENV BOULDER_CONFIG /go/src/github.com/letsencrypt/boulder/test/boulder-config.json

# Copy in the Boulder sources
COPY . /go/src/github.com/letsencrypt/boulder

# Build Boulder
RUN go install -tags pkcs11 \
  github.com/letsencrypt/boulder/cmd/activity-monitor \
  github.com/letsencrypt/boulder/cmd/boulder \
  github.com/letsencrypt/boulder/cmd/boulder-ca \
  github.com/letsencrypt/boulder/cmd/boulder-ra \
  github.com/letsencrypt/boulder/cmd/boulder-sa \
  github.com/letsencrypt/boulder/cmd/boulder-va \
  github.com/letsencrypt/boulder/cmd/boulder-wfe

CMD ["bash", "-c", "rsyslogd && /go/bin/boulder"]
