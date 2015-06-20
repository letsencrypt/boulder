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
  if $*; then
    echo "success: $*"
  else
    FAILURE=1
    echo "failure: $*"
  fi
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
    run go test -tags pkcs11 -covermode=count -coverprofile=${dir}.coverprofile ./${dir}/
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

  run go test -tags pkcs11 ${dirlist}
fi

if [ -z "$LETSENCRYPT_VENV" ]; then
  DEFAULT_LETSENCRYPT_PATH="/tmp/letsencrypt"
  LETSENCRYPT_VENV="$DEFAULT_LETSENCRYPT_PATH/venv"

  run git clone https://www.github.com/letsencrypt/lets-encrypt-preview.git $DEFAULT_LETSENCRYPT_PATH

  cd $DEFAULT_LETSENCRYPT_PATH
  run virtualenv --no-site-packages -p python2 ./venv && \
    ./venv/bin/pip install -r requirements.txt -e .
  cd -
fi

export LETSENCRYPT_VENV

[ ${FAILURE} == 0 ] && run python test/amqp-integration-test.py

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
