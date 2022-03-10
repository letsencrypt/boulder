#!/usr/bin/env bash
#
# Make a Boulder Debian package at $PWD.
#

#
# Setup Dependencies
#

sudo apt-get install -y --no-install-recommends \
  ruby \
  ruby-dev \
  gcc

# Parse our production Go version from our docker-compose file.
GO_VERSION=$(grep "BOULDER_TOOLS_TAG:-" docker-compose.yml | sed -e 's/.*-go//' -e 's/_.*//')

# Download and unpack our production go version.
wget -O go.tgz "https://dl.google.com/go/go${GO_VERSION}.linux-amd64.tar.gz"
sudo tar -C /usr/local -xzf go.tgz
export PATH=/usr/local/go/bin:$PATH

# Install fpm, this is used in our Makefile to package Boulder as a deb or rpm.
sudo gem install --no-document fpm

#
# Build
#

# Set $ARCHIVEDIR to our current directory. If left unset our Makefile will set
# it to /tmp.
export ARCHIVEDIR="${PWD}"

# Build Boulder and package and produce a Debian package.
make deb
