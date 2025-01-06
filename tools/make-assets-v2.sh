#!/usr/bin/env bash
#
# Build a .deb and a .tar.gz containing the Boulder binary and some supporting test files.
#
# This script expects to run on Ubuntu.

set -feuxo pipefail

cd "$(realpath -- $(dirname -- "$0")../ )"

sudo apt-get install -y --no-install-recommends \
  make \
  gnupg \
  git \
  curl

# Download and unpack our production go version. Ensure that $GO_VERSION is
# already set in the environment (e.g. by the github actions release workflow).
./tools/fetch-and-verify-go.sh "${GO_VERSION}"
sudo tar -C /usr/local -xzf go.tar.gz
export PATH=/usr/local/go/bin:$PATH

make

ARCHIVEDIR="${PWD}"
BOULDER="${PWD}"
BUILD="$(mktemp -d)"

TARGET="${BUILD}"/opt/boulder

mkdir -p "${TARGET}/bin"
cp -a bin/admin "${TARGET}/bin/"
cp -a bin/boulder "${TARGET}/bin/"
cp -a bin/ceremony "${TARGET}/bin/"
cp -a bin/ct-test-srv "${TARGET}/bin/"

copydir () {
    mkdir -p "${TARGET}/$1"
    cp -a "${BOULDER}/$1" "${TARGET}/$1"
}

mkdir -p "${TARGET}/test"
cp -a "${BOULDER}/test/config/" "${TARGET}/test/config/"

mkdir -p "${TARGET}/sa"
cp -a "${BOULDER}/sa/db/" "${TARGET}/sa/db/"

cp -a "${BOULDER}/data/" "${TARGET}/data/"

# Set $VERSION to be a simulacrum of what is set in other build environments.
export VERSION="${GO_VERSION}.$(date +%s)"
COMMIT_ID="$(git rev-parse --short=8 HEAD)"

mkdir "${BUILD}"/DEBIAN
cat > "${BUILD}"/DEBIAN/control <<-EOF
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
