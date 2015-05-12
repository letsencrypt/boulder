#!/bin/bash
# Run all tests and coverage checks. Called from Travis automatically, also
# suitable to run manually. See list of prerequisite packages in .travis.yml
if type realpath 2>&1 >/dev/null; then
  cd $(realpath $(dirname $0))
fi

FAILURE=0

run() {
  $* || FAILURE=1
}

doTest() {
  local dir=$1
  run go test -covermode=count -coverprofile=${dir}.coverprofile ./${dir}/
}

# Path for installed go package binaries. If yours is different, override with
# GOBIN=/my/path/to/bin ./test.sh
GOBIN=${GOBIN:-$HOME/gopath/bin}

# Ask vet to check in on things
run go vet -x ./...

[ -e $GOBIN/golint ] && run $GOBIN/golint ./...

# Ensure SQLite is installed so we don't recompile it each time
go install ./Godeps/_workspace/src/github.com/mattn/go-sqlite3

# All the subdirectories
doTest analysis
doTest ca
#doTest cmd
doTest core
doTest log
doTest policy
doTest ra
doTest rpc
doTest sa
doTest test
doTest va
#doTest vendor
doTest wfe

[ -e $GOBIN/gover ] && run $GOBIN/gover

if [ "${TRAVIS}" == "true" ] ; then
  # We don't use the run function here because sometimes goveralls fails to
  # contact the server and exits with non-zero status, but we don't want to
  # treat that as a failure.
  $GOBIN/goveralls -coverprofile=gover.coverprofile -service=travis-ci
fi

exit ${FAILURE}
