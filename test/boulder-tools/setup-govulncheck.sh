#!/bin/bash
set -feuxo pipefail

# Implements a filesystem structure that can serve as an API for govulncheck.
# See https://go.dev/security/vuln/database for more information.
#
# TODO(@pgporada) Remove this if we decide that the boulder-tools container can
# have network access.

GVCDIR="/tmp/govulncheck-local-database"
if [ -d "${GVCDIR}" ]; then
    rm -rf "${GVCDIR}"
fi

mkdir -p "${GVCDIR}"
cd "${GVCDIR}"

# Check out only the data we need from this repository.
git clone -n \
	--depth=1 \
	--filter=tree:0 \
	https://github.com/golang/vulndb .
git sparse-checkout set --no-cone data/osv
git checkout
mv data/osv/ ID/
mkdir -p index
rm -rf data .git

for FILE in {db,modules,vulns}.json; do
    wget "https://vuln.go.dev/index/${FILE}" -O "index/${FILE}"
done

echo "Done"
