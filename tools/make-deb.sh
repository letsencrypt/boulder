#!/usr/bin/env bash
#
# Produce a .deb from a built Boulder plus helper files.
#
# This script expects to run on Ubuntu, as configured on GitHub Actions runners
# (with curl, make, and git installed).
#
# -e Stops execution in the instance of a command or pipeline error.
# -u Treat unset variables as an error and exit immediately.
set -eu
cd "$(realpath -- "$(dirname -- "$0")")/.."

BUILD="$(mktemp -d)"

mkdir -p "${BUILD}/opt"
cp -a /opt/boulder "${BUILD}/opt/boulder"

mkdir -p "${BUILD}/DEBIAN"
cat > "${BUILD}/DEBIAN/control" <<-EOF
Package: boulder
Version: 1:${VERSION}
License: Mozilla Public License v2.0
Vendor: ISRG
Architecture: amd64
Maintainer: Community
Section: default
Priority: extra
Homepage: https://github.com/letsencrypt/boulder
Description: Boulder is an ACME-compatible X.509 Certificate Authority
EOF

dpkg-deb -Zgzip -b "${BUILD}" "boulder-${VERSION}-${COMMIT_ID}.x86_64.deb"
