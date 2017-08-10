#!/bin/bash

# Travis does shallow clones, so there is no master branch present.
# But test-no-outdated-migrations.sh needs to check diffs against master.
# Fetch just the master branch from origin.
( git fetch origin master
git branch master FETCH_HEAD ) &
