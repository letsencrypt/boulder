#!/bin/bash
set -o xtrace

# Travis does shallow clones, so there is no master branch present.
# But test-no-outdated-migrations.sh needs to check diffs against master.
# Fetch just the master branch from origin.
( git fetch origin master
git branch master FETCH_HEAD ) &
# Github-PR-Status secret
if [ -n "$encrypted_53b2630f0fb4_key" ]; then
  openssl aes-256-cbc \
    -K $encrypted_53b2630f0fb4_key -iv $encrypted_53b2630f0fb4_iv \
    -in test/github-secret.json.enc -out /tmp/github-secret.json -d
fi

travis_retry go get \
  golang.org/x/tools/cmd/vet \
  golang.org/x/tools/cmd/cover \
  github.com/golang/lint/golint \
  github.com/mattn/goveralls \
  github.com/modocache/gover \
  github.com/jcjones/github-pr-status \
  github.com/jsha/listenbuddy &

(wget https://github.com/jsha/boulder-tools/raw/master/goose.gz &&
 mkdir $GOPATH/bin &&
 zcat goose.gz > $GOPATH/bin/goose &&
 chmod +x $GOPATH/bin/goose) &

# Wait for all the background commands to finish.
wait

# Boulder consists of multiple Go packages, which
# refer to each other by their absolute GitHub path,
# e.g. github.com/letsencrypt/boulder/analysis. That means, by default, if
# someone forks the repo, Travis won't pass on their own repo. To fix that,
# we add a symlink.
mkdir -p $TRAVIS_BUILD_DIR $GOPATH/src/github.com/letsencrypt
if [ ! -d $GOPATH/src/github.com/letsencrypt/boulder ] ; then
  ln -s $TRAVIS_BUILD_DIR $GOPATH/src/github.com/letsencrypt/boulder
fi

set +o xtrace
