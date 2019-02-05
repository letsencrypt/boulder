#!/bin/bash
set -e
set -o xtrace

# Check that `minica` is installed
command -v minica >/dev/null 2>&1 || {
  echo >&2 "No 'minica' command available.";
  echo >&2 "Check your GOPATH and run: 'go get github.com/jsha/minica'.";
  exit 1;
}

for HOSTNAME in admin-revoker.boulder expiration-mailer.boulder \
  ocsp-updater.boulder orphan-finder.boulder wfe.boulder akamai-purger.boulder ; do
  minica -domains ${HOSTNAME}
done

for SERVICE in publisher ra ca sa va ; do
  minica -domains "${SERVICE}.boulder,${SERVICE}1.boulder,${SERVICE}2.boulder"
done
