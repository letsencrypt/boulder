#!/bin/bash

function die() {
  if [ ! -z "$1" ]; then
    echo $1 > /dev/stderr
  fi
  exit 1
}

mysql -u root -e "create database boulder_test; grant all privileges on boulder_test.* to 'boulder'@'localhost'" || die "unable to create boulder_test"
echo "created boulder_test database"
