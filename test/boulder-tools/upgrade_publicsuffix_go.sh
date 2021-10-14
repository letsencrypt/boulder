#!/usr/bin/env bash

# -e Stops execution in the instance of a command or pipeline error.
# -u Treat unset variables as an error and exit immediately.
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

print_heading "Updating weppos/publicsuffix-go to the latest commit"

# Fetches the latest version of weppos/publicsuffix-go and updates the go.mod
# and go.sum files.
go get "github.com/weppos/publicsuffix-go@master"

# Updates the contents of boulder's (vendored) copy of weppos/publicsuffix-go.
go mod vendor

# Counts additions and removals using git diff and concatenates it with labels
# using awk. This count is used in the PR body and commit message.
git diff --numstat | grep "vendor/github.com/weppos/publicsuffix-go/publicsuffix/rules.go" | awk '{ print $1 " additions and " $2 " removals" }'

# Stages the only files that should be committed.
git add vendor go.mod go.sum

# Because set -e stops execution in the instance of a command or pipeline error;
# if we got here we assume success
STATUS="SUCCESS"
