#!/bin/bash
set -e
set -o xtrace

# Check that `minica` is installed
command -v minica >/dev/null 2>&1 || {
  echo >&2 "No 'minica' command available.";
  echo >&2 "Check your GOPATH and run: 'go get github.com/jsha/minica'.";
  exit 1;
}

for HOSTNAME in admin-revoker.boulder ca.boulder expiration-mailer.boulder \
  ocsp-updater.boulder orphan-finder.boulder publisher.boulder ra.boulder \
  sa.boulder va.boulder wfe.boulder ; do
  minica -domains ${HOSTNAME}
done
