#!/usr/bin/env bash
#
# This script expects to run on Ubuntu. It installs the dependencies necessary
# to build Boulder and produce a Debian Package. The actual build and packaging
# is handled by a call to Make.
#

# -e Stops execution in the instance of a command or pipeline error.
# -u Treat unset variables as an error and exit immediately.
set -eu

#
# Setup Dependencies
#

sudo apt-get install -y --no-install-recommends \
  ruby \
  ruby-dev \
  gcc

# Download and unpack our production go version. Ensure that $GO_VERSION is
# already set in the environment (e.g. by the github actions release workflow).
$(dirname -- "${0}")/fetch-and-verify-go.sh "${GO_VERSION}"
sudo tar -C /usr/local -xzf go.tar.gz
export PATH=/usr/local/go/bin:$PATH

# Install fpm, this is used in our Makefile to package Boulder as a deb.
sudo gem install --no-document -v 1.14.0 fpm

#
# Build
#

# Set $ARCHIVEDIR to our current directory. If left unset our Makefile will set
# it to /tmp.
export ARCHIVEDIR="${PWD}"

# Set $VERSION to be a simulacrum of what is set in other build environments.
export VERSION="${GO_VERSION}.$(date +%s)"

# Build Boulder.
make

# Produce a .deb and a tar.gz file in $PWD.
make deb tar

# Produce a .deb and .tar.gz in $PWD without using `make` or `fpm`. The
# resulting files will be named `boulder-newpkg-*`. Eventually this code
# will be used to produce the regular `boulder-*` packages.
BOULDER="${PWD}"
BUILD="$(mktemp -d)"
TARGET="${BUILD}/opt/boulder"

COMMIT_ID="$(git rev-parse --short=8 HEAD)"

mkdir -p "${TARGET}/bin"
for NAME in admin boulder ceremony ct-test-srv ; do
  cp -a "bin/${NAME}" "${TARGET}/bin/"
done

mkdir -p "${TARGET}/test"
cp -a "${BOULDER}/test/config/" "${TARGET}/test/config/"

mkdir -p "${TARGET}/sa"
cp -a "${BOULDER}/sa/db/" "${TARGET}/sa/db/"

cp -a "${BOULDER}/data/" "${TARGET}/data/"

mkdir "${BUILD}/DEBIAN"
cat > "${BUILD}/DEBIAN/control" <<-EOF
Package: boulder
Version: 1:${VERSION}
License: Mozilla Public License v2.0
Vendor: ISRG
Architecture: arm64
Maintainer: Community
Section: default
Priority: extra
Homepage: https://github.com/letsencrypt/boulder
Description: Boulder is an ACME-compatible X.509 Certificate Authority
EOF

dpkg-deb -Zgzip -b "${BUILD}" "${ARCHIVEDIR}/boulder-newpkg-${VERSION}-${COMMIT_ID}.x86_64.deb"
tar -C "${TARGET}" -cpzf "${ARCHIVEDIR}/boulder-newpkg-${VERSION}-${COMMIT_ID}.amd64.tar.gz" .
