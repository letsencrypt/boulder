#!/usr/bin/env bash
#
# Produce a .deb package from a built Boulder container.
#
# This script is executed inside the Boulder Docker container by container-build.sh.
# It packages the Boulder binary and assets into a Debian package for distribution.
#
# -e Stops execution in the instance of a command or pipeline error.
# -u Treat unset variables as an error and exit immediately.
set -eu
cd "$(realpath -- "$(dirname -- "$0")")/.."

if [ -z "${VERSION:-}" ]; then echo "VERSION not set"; exit 1; fi
if [ -z "${COMMIT_ID:-}" ]; then echo "COMMIT_ID not set"; exit 1; fi
if [ -z "${ARCH:-}" ]; then echo "ARCH not set"; exit 1; fi

BUILD="$(mktemp -d)"
mkdir -p "${BUILD}/opt"
cp -a /opt/boulder "${BUILD}/opt/boulder"

mkdir -p "${BUILD}/DEBIAN"
cat >"${BUILD}/DEBIAN/control" <<-EOF
Package: boulder
Version: 1:${VERSION}
License: Mozilla Public License v2.0
Vendor: ISRG
Architecture: ${ARCH}
Maintainer: Community
Section: default
Priority: extra
Homepage: https://github.com/letsencrypt/boulder
Description: Boulder is an ACME-compatible X.509 Certificate Authority
EOF

dpkg-deb -Zgzip -b "${BUILD}" "boulder-${VERSION}-${COMMIT_ID}.${ARCH}.deb"
