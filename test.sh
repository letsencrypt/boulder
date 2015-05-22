#!/bin/bash
# Run all tests and coverage checks. Called from Travis automatically, also
# suitable to run manually. See list of prerequisite packages in .travis.yml
if type realpath >/dev/null 2>&1 ; then
  cd $(realpath $(dirname $0))
fi

FAILURE=0

TESTDIRS="analysis \
          ca \
          core \
          log \
          policy \
          ra \
          rpc \
          sa \
          test \
          va \
          wfe"
          # cmd
          # Godeps

run() {
  echo "$*"
  $* || FAILURE=1
}


# Path for installed go package binaries. If yours is different, override with
# GOBIN=/my/path/to/bin ./test.sh
GOBIN=${GOBIN:-$HOME/gopath/bin}

# Ask vet to check in on things
run go vet -x ./...

[ -e $GOBIN/golint ] && run $GOBIN/golint ./...

# Ensure SQLite is installed so we don't recompile it each time
go install ./Godeps/_workspace/src/github.com/mattn/go-sqlite3

if [ "${TRAVIS}" == "true" ] ; then
  # Run each test by itself for Travis, so we can get coverage
  for dir in ${TESTDIRS}; do
    run go test -covermode=count -coverprofile=${dir}.coverprofile ./${dir}/
  done

  # Gather all the coverprofiles
  [ -e $GOBIN/gover ] && run $GOBIN/gover

  # We don't use the run function here because sometimes goveralls fails to
  # contact the server and exits with non-zero status, but we don't want to
  # treat that as a failure.
  [ -e $GOBIN/goveralls ] && $GOBIN/goveralls -coverprofile=gover.coverprofile -service=travis-ci
else
  # Run all the tests together if local, for speed
  dirlist=""

  for dir in ${TESTDIRS}; do
    dirlist="${dirlist} ./${dir}/"
  done

  run go test ${dirlist}
fi

unformatted=$(find . -name "*.go" -not -path "./Godeps/*" -print | xargs -n1  gofmt -l)
if [ "x${unformatted}" != "x" ] ; then
  echo "Unformatted files found; setting failure state."
  echo "Please run 'go fmt' on each of these files and amend your commit to continue."
  FAILURE=1
  for f in ${unformatted}; do
    echo "- ${f}"
  done
fi

exit ${FAILURE}
