#!/bin/bash
# Boulder consists of multiple Go packages, which
# refer to each other by their absolute GitHub path,
# That means, by default, if someone forks the repo,
# Travis won't pass on their own repo. To fix that,
# we move the source directory.
if [ ! -d $GOPATH/src/github.com/letsencrypt/boulder ] ; then
  mkdir -p $TRAVIS_BUILD_DIR $GOPATH/src/github.com/letsencrypt
  mv $TRAVIS_BUILD_DIR $GOPATH/src/github.com/letsencrypt/boulder
fi

# Travis does shallow clones, so there is no master branch present.
# But test-no-outdated-migrations.sh needs to check diffs against master.
# Fetch just the master branch from origin.
( git fetch origin master
git branch master FETCH_HEAD ) &
