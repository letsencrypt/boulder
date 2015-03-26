#!/bin/bash 
# Run all tests and coverage checks. Called from Travis automatically, also
# suitable to run manually. See list of prerequisite packages in .travis.yml
cd $(realpath $(dirname $0))

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

# All the subdirectories
doTest analysis
doTest ca
#doTest cmd
doTest core
doTest jose
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
  run $GOBIN/goveralls -coverprofile=gover.coverprofile -service=travis-ci
fi

exit ${FAILURE}
