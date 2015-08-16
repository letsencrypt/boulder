FROM golang:1.5rc1

MAINTAINER J.C. Jones "jjones@letsencrypt.org"
MAINTAINER William Budington "bill@eff.org"

# Add node.js key to apt-key safely
RUN curl -s https://deb.nodesource.com/gpgkey/nodesource.gpg.key | gpg --import && \
  gpg --export 9FD3B784BC1C6FC31A8A0A1C1655A0AB68576280 | apt-key add -

# Install dependencies packages
RUN apt-get update && \
  apt-get install -y --no-install-recommends \
    apt-transport-https && \
  echo deb https://deb.nodesource.com/node_0.12 jessie main > /etc/apt/sources.list.d/nodesource.list && \
  apt-get update && \
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    libltdl-dev \
    rsyslog \
    nodejs \
    lsb-release \
    rabbitmq-server \
    mariadb-server \
    git-core && \
  apt-get clean && \
  rm -rf /var/lib/apt/lists/* \
    /tmp/* \
    /var/tmp/*

# Boulder exposes its web application at port TCP 4000
EXPOSE 4000

# Assume the configuration is in /etc/boulder
ENV BOULDER_CONFIG /go/src/github.com/letsencrypt/boulder/test/boulder-config.json

# Get the Let's Encrypt client
RUN git clone https://www.github.com/letsencrypt/lets-encrypt-preview.git /letsencrypt
WORKDIR /letsencrypt
RUN ./bootstrap/debian.sh && \
  apt-get clean && \
  rm -rf /var/lib/apt/lists/* \
    /tmp/* \
    /var/tmp/*
RUN virtualenv --no-site-packages -p python2 venv && \
  ./venv/bin/pip install -r requirements.txt -e acme -e .[dev,docs,testing] -e letsencrypt-apache -e letsencrypt-nginx

ENV LETSENCRYPT_PATH /letsencrypt

# Copy in the Boulder sources
COPY . /go/src/github.com/letsencrypt/boulder

# Build Boulder
RUN go install \
  github.com/letsencrypt/boulder/cmd/activity-monitor \
  github.com/letsencrypt/boulder/cmd/boulder-ca \
  github.com/letsencrypt/boulder/cmd/boulder-ra \
  github.com/letsencrypt/boulder/cmd/boulder-sa \
  github.com/letsencrypt/boulder/cmd/boulder-va \
  github.com/letsencrypt/boulder/cmd/boulder-wfe

WORKDIR /go/src/github.com/letsencrypt/boulder
CMD ["bash", "-c", "service mysql start && \
service rsyslog start && \
service rabbitmq-server start && \
cd /go/src/github.com/letsencrypt/boulder/ && \
./test/create_db.sh && \
WFE_LISTEN_ADDR=0.0.0.0:4000 ./start.py"]
