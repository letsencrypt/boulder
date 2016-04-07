#!/bin/bash
# Run all tests and coverage checks. Called from Travis automatically, also
# suitable to run manually. See list of prerequisite packages in .travis.yml
if type realpath >/dev/null 2>&1 ; then
  cd $(realpath $(dirname $0))
fi

# The list of segments to run. To run only some of these segments, pre-set the
# RUN variable with the ones you want (see .travis.yml for an example).
# Order doesn't matter. Note: godep-restore is specifically left out of the
# defaults, because we don't want to run it locally (would be too disruptive to
# GOPATH).
RUN=${RUN:-vet lint fmt migrations unit integration}

# The list of segments to hard fail on, as opposed to continuing to the end of
# the unit tests before failing.  By defuault, we only hard-fail for gofmt,
# since its errors are common and easy to fix.
HARDFAIL=${HARDFAIL:-fmt}

FAILURE=0

TESTPATHS=$(go list -f '{{ .ImportPath }}' ./...)

# We need to know, for github-pr-status, what the triggering commit is.
# Assume first it's the travis commit (for builds of master), unless we're
# a PR, when it's actually the first parent.
TRIGGER_COMMIT=${TRAVIS_COMMIT}
if [ "x${TRAVIS_PULL_REQUEST}" != "x" ] ; then
  revs=$(git rev-list --parents -n 1 HEAD)
  # The trigger commit is the last ID in the space-delimited rev-list
  TRIGGER_COMMIT=${revs##* }
fi

GITHUB_SECRET_FILE="/tmp/github-secret.json"

start_context() {
  CONTEXT="$1"
  printf "[%16s] Starting\n" ${CONTEXT}
}

end_context() {
  printf "[%16s] Done\n" ${CONTEXT}
  if [ ${FAILURE} != 0 ] && [[ ${HARDFAIL} =~ ${CONTEXT} ]]; then
    echo "--------------------------------------------------"
    echo "---        A unit test or tool failed.         ---"
    echo "---   Stopping before running further tests.   ---"
    echo "--------------------------------------------------"
    exit ${FAILURE}
  fi
  CONTEXT=""
}

update_status() {
  if ([ "${TRAVIS}" == "true" ] && [ "x${CONTEXT}" != "x" ]) && [ -f "${GITHUB_SECRET_FILE}" ]; then
    github-pr-status --authfile $GITHUB_SECRET_FILE \
      --owner "letsencrypt" --repo "boulder" \
      status --sha "${TRIGGER_COMMIT}" --context "${CONTEXT}" \
      --url "https://travis-ci.org/letsencrypt/boulder/builds/${TRAVIS_BUILD_ID}" $*
  fi
}

function run() {
  echo "$@"
  "$@" 2>&1
  local status=$?

  if [ ${status} -eq 0 ]; then
    update_status --state success
  else
    FAILURE=1
    update_status --state failure
    echo "[!] FAILURE: $@"
  fi

  return ${status}
}

function run_and_comment() {
  echo "$@"
  result=$("$@" 2>&1)
  cat <<<"${result}"

  if [ "x${result}" == "x" ]; then
    update_status --state success
  else
    FAILURE=1
    update_status --state failure
    echo "[!] FAILURE: $@"
  fi

  # If this is a travis PR run, post a comment
  if [ "x${TRAVIS}" != "x" ] && [ "${TRAVIS_PULL_REQUEST}" != "false" ] && [ -f "${GITHUB_SECRET_FILE}" ] ; then
    # If the output is non-empty, post a comment and mark this as a failure
    if [ -n "${result}" ] ; then
      echo $'```\n'${result}$'\n```' | github-pr-status --authfile $GITHUB_SECRET_FILE \
        --owner "letsencrypt" --repo "boulder" \
        comment --pr "${TRAVIS_PULL_REQUEST}" -b -
    fi
  fi
}

function die() {
  if [ ! -z "$1" ]; then
    echo $1 > /dev/stderr
  fi
  exit 1
}

function build_letsencrypt() {
  # Test for python 2 installs with the usual names.
  if hash python2 2>/dev/null; then
    PY=python2
  elif hash python2.7 2>/dev/null; then
    PY=python2.7
  else
    die "unable to find a python2 or python2.7 binary in \$PATH"
  fi

  run git clone \
    https://www.github.com/letsencrypt/letsencrypt.git \
    $LETSENCRYPT_PATH || exit 1

  cd $LETSENCRYPT_PATH

  run virtualenv --no-site-packages -p $PY ./venv
  run ./venv/bin/pip install -U setuptools
  run ./venv/bin/pip install -U pip
  run ./venv/bin/pip install -e acme -e . -e letsencrypt-apache -e letsencrypt-nginx

  cd -
}

function run_unit_tests() {
  if [ "${TRAVIS}" == "true" ]; then

    # The deps variable is the imports of the packages under test that
    # are not stdlib packages. We can then install them with the race
    # detector enabled to prevent our individual `go test` calls from
    # building them multiple times.
    all_shared_imports=$(go list -f '{{ join .Imports "\n" }}' $TESTPATHS | sort | uniq)
    deps=$(go list -f '{{ if not .Standard }}{{ .ImportPath }}{{ end }}' ${all_shared_imports})
    echo "go installing race detector enabled dependencies"
    go install -race $deps

    # Run each test by itself for Travis, so we can get coverage
    for path in ${TESTPATHS}; do
      dir=$(basename $path)
      go test -race -cover -coverprofile=${dir}.coverprofile ${path} || FAILURE=1
    done

    # Gather all the coverprofiles
    [ -e $GOBIN/gover ] && run $GOBIN/gover

    # We don't use the run function here because sometimes goveralls fails to
    # contact the server and exits with non-zero status, but we don't want to
    # treat that as a failure.
    [ -e $GOBIN/goveralls ] && $GOBIN/goveralls -coverprofile=gover.coverprofile -service=travis-ci
  else
    # When running locally, we skip the -race flag for speedier test runs. We
    # also pass -p 1 to require the tests to run serially instead of in
    # parallel. This is because our unittests depend on mutating a database and
    # then cleaning up after themselves. If they run in parallel, they can fail
    # spuriously because one test is modifying a table (especially
    # registrations) while another test is reading it.
    # https://github.com/letsencrypt/boulder/issues/1499
    run go test -p 1 $GOTESTFLAGS ./...
  fi
}

# Path for installed go package binaries. If yours is different, override with
# GOBIN=/my/path/to/bin ./test.sh
GOBIN=${GOBIN:-$HOME/gopath/bin}

#
# Run Go Vet, a correctness-focused static analysis tool
#
if [[ "$RUN" =~ "vet" ]] ; then
  start_context "vet"
  run_and_comment go vet ./...
  end_context #vet
fi

#
# Run Go Lint, a style-focused static analysis tool
#
if [[ "$RUN" =~ "lint" ]] ; then
  start_context "lint"
  run_and_comment golint -min_confidence=0.81 ./...
  end_context #lint
fi

#
# Ensure all files are formatted per the `go fmt` tool
#
if [[ "$RUN" =~ "fmt" ]] ; then
  start_context "fmt"
  check_gofmt() {
    unformatted=$(find . -name "*.go" -not -path "./Godeps/*" -print | xargs -n1 gofmt -l)
    if [ "x${unformatted}" == "x" ] ; then
      return 0
    else
      V="Unformatted files found.
      Please run 'go fmt' on each of these files and amend your commit to continue."

      for f in ${unformatted}; do
        V=$(printf "%s\n - %s" "${V}" "${f}")
      done

      # Print to stdout
      printf "%s\n\n" "${V}"
      [ "${TRAVIS}" == "true" ] || exit 1 # Stop here if running locally
      return 1
    fi
  }

  run_and_comment check_gofmt
  end_context #fmt
fi

if [[ "$RUN" =~ "migrations" ]] ; then
  start_context "migrations"
  run_and_comment ./test/test-no-outdated-migrations.sh
  end_context #"migrations"
fi

#
# Unit Tests.
#
if [[ "$RUN" =~ "unit" ]] ; then
  run_unit_tests
  # If the unittests failed, exit before trying to run the integration test.
  if [ ${FAILURE} != 0 ]; then
    echo "--------------------------------------------------"
    echo "---        A unit test or tool failed.         ---"
    echo "--- Stopping before running integration tests. ---"
    echo "--------------------------------------------------"
    exit ${FAILURE}
  fi
fi

#
# Integration tests
#
if [[ "$RUN" =~ "integration" ]] ; then
  # Set context to integration, and force a pending state
  start_context "integration"
  update_status --state pending --description "Integration Tests in progress"

  if [ -z "$LETSENCRYPT_PATH" ]; then
    export LETSENCRYPT_PATH=$(mktemp -d -t leXXXX)
    echo "------------------------------------------------"
    echo "--- Checking out letsencrypt client is slow. ---"
    echo "--- Recommend setting \$LETSENCRYPT_PATH to  ---"
    echo "--- client repo with initialized virtualenv  ---"
    echo "------------------------------------------------"
    build_letsencrypt
  elif [ ! -d "${LETSENCRYPT_PATH}" ]; then
    build_letsencrypt
  fi

  source ${LETSENCRYPT_PATH}/venv/bin/activate

  python test/integration-test.py --all
  case $? in
    0) # Success
      update_status --state success
      ;;
    1) # Python client failed
      update_status --state success --description "Python integration failed."
      FAILURE=1
      ;;
    2) # Node client failed
      update_status --state failure --description "NodeJS integration failed."
      FAILURE=1
      ;;
    *) # Error occurred
      update_status --state error --description "Unknown error occurred."
      FAILURE=1
      ;;
  esac
  end_context #integration
fi

# Run godep-restore (happens only in Travis) to check that the hashes in
# Godeps.json really exist in the remote repo and match what we have.
if [[ "$RUN" =~ "godep-restore" ]] ; then
  start_context "godep-restore"
  run_and_comment godep restore
  # Run godep save and do a diff, to ensure that the version we got from
  # `godep restore` matched what was in the remote repo. We only do this on
  # builds of the main fork (not PRs from external contributors), because godep
  # rewrites import paths to the path of the fork we're building from, which
  # creates spurious diffs if we're not building from the main fork.
  # Once we switch to Go 1.6's imports and don't need rewriting anymore, we can
  # do this for all builds.
  if [[ "${TRAVIS_REPO_SLUG}" == "letsencrypt/boulder" ]] ; then
    run_and_comment godep save -r ./...
    run_and_comment git diff --exit-code Godeps/_workspace/
  fi
  end_context #godep-restore
fi

exit ${FAILURE}
