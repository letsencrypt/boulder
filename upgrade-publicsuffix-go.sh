#!/usr/bin/env bash

# -e Stops execution in the instance of a command or pipeline error -u Treat
# unset variables as an error and exit immediately
set -eu

STATUS="FAILURE"

function exit_msg() {
  # complain to STDERR and exit with error
  echo "$*" >&2
  exit 2
}

function print_outcome() {
  if [ "$STATUS" == SUCCESS ]
  then
    echo -e "\e[32m"$STATUS"\e[0m"
  else
    echo -e "\e[31m"$STATUS"\e[0m"
  fi
}

function print_heading {
  echo
  echo -e "\e[34m\e[1m"$1"\e[0m"
}

# On EXIT, trap and print outcome.
trap "print_outcome" EXIT

print_heading "Fetching SHA of the latest publicsuffix-go commit"

# Uses git ls-remote to pull the heads of the publicsuffix-go repo, searches for
# master and captures the commit SHA.
SHA=$(git ls-remote --heads https://github.com/weppos/publicsuffix-go.git | grep "refs/heads/master"| cut -c1-12)

# Make sure the commit SHA that we think we captured actually exists.
if [ -z "$SHA" ]
then
    exit_msg "Couldn't find the SHA of most recent commit to the master branch of https://github.com/weppos/publicsuffix-go.git"
else
    echo "OK"
    print_heading "Fetching weppos/publicsuffix-go@$SHA"
    
    # Fetches the latest version of the dependency at the commit SHA, updates
    # the go.mod and go.sum files.
    go get "github.com/weppos/publicsuffix-go@$SHA"
    
    # Updates the contents of boulder's (vendored) copy of
    # weppos/publicsuffix-go.
    go mod vendor
    
    # Counts additions and removals using git diff and concatenates it with
    # labels using awk.
    git diff --numstat | grep "vendor/github.com/weppos/publicsuffix-go/publicsuffix/rules.go" | awk '{ print $1 " additions and " $2 " removals" }'

    # Stages the only files that should be committed.
    git add vendor go.mod go.sum

    # Because set -e stops execution in the instance of a command or pipeline
    # error; if we got here we assume success
    STATUS="SUCCESS"
fi
