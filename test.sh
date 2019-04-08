#!/bin/bash
# Run all tests and coverage checks. Called from Travis automatically, also
# suitable to run manually. See list of prerequisite packages in .travis.yml
if type realpath >/dev/null 2>&1 ; then
  cd $(realpath $(dirname $0))
fi

set -ex pipefail
TRAVIS=${TRAVIS:-false}

# The list of segments to run. To run only some of these segments, pre-set the
# RUN variable with the ones you want (see .travis.yml for an example).
# Order doesn't matter. Note: godep-restore is specifically left out of the
# defaults, because we don't want to run it locally (would be too disruptive to
# GOPATH). We also omit coverage by default on local runs because it generates
# artifacts on disk that aren't needed.
RUN=${RUN:-vet fmt migrations unit integration errcheck ineffassign dashlint}

function run_and_expect_silence() {
  echo "$@"
  result_file=$(mktemp -t bouldertestXXXX)
  "$@" 2>&1 | tee ${result_file}

  # Fail if result_file is nonempty.
  if [ -s ${result_file} ]; then
    rm ${result_file}
    exit 1
  fi
  rm ${result_file}
}

function run_unit_tests() {
  if [ "${TRAVIS}" == "true" ]; then
    # Run the full suite of tests once with the -race flag. Since this isn't
    # running tests individually we can't collect coverage information.
    echo "running test suite with race detection"
    go test -race -p 1 ./...
  else
    # When running locally, we skip the -race flag for speedier test runs. We
    # also pass -p 1 to require the tests to run serially instead of in
    # parallel. This is because our unittests depend on mutating a database and
    # then cleaning up after themselves. If they run in parallel, they can fail
    # spuriously because one test is modifying a table (especially
    # registrations) while another test is reading it.
    # https://github.com/letsencrypt/boulder/issues/1499
    go test -p 1 ./...
  fi
}

function run_test_coverage() {
  # Run each test by itself for Travis, so we can get coverage. We skip using
  # the -race flag here because we have already done a full test run with
  # -race in `run_unit_tests` and it adds substantial overhead to run every
  # test with -race independently
  echo "running test suite with coverage enabled and without race detection"
  go test -p 1 -cover -coverprofile=${dir}.coverprofile ./...

  # Gather all the coverprofiles
  gover

  # We don't use the run function here because sometimes goveralls fails to
  # contact the server and exits with non-zero status, but we don't want to
  # treat that as a failure.
  goveralls -v -coverprofile=gover.coverprofile -service=travis-ci
}

#
# Run Go Vet, a correctness-focused static analysis tool
#
if [[ "$RUN" =~ "vet" ]] ; then
  run_and_expect_silence go vet ./...
fi

#
# Ensure all files are formatted per the `go fmt` tool
#
if [[ "$RUN" =~ "fmt" ]] ; then
  run_and_expect_silence go fmt ./...
fi

if [[ "$RUN" =~ "migrations" ]] ; then
  run_and_expect_silence ./test/test-no-outdated-migrations.sh
fi

#
# Unit Tests.
#
if [[ "$RUN" =~ "unit" ]] ; then
  run_unit_tests
fi

#
# Unit Test Coverage.
#
if [[ "$RUN" =~ "coverage" ]] ; then
  run_test_coverage
fi

#
# Integration tests
#
if [[ "$RUN" =~ "integration" ]] ; then
  args=("--chisel")
  args+=("--load")
  if [[ "${INT_FILTER:-}" != "" ]]; then
    args+=("--filter" "${INT_FILTER}")
  fi
  if [[ "${INT_SKIP_SETUP:-}" =~ "true" ]]; then
    args+=("--skip-setup")
  fi

  source ${CERTBOT_PATH:-/certbot}/${VENV_NAME:-venv}/bin/activate
  DIRECTORY=http://boulder:4000/directory \
    python2 test/integration-test.py "${args[@]}"
fi

# Run godep-restore (happens only in Travis) to check that the hashes in
# Godeps.json really exist in the remote repo and match what we have.
if [[ "$RUN" =~ "godep-restore" ]] ; then
  run_and_expect_silence godep restore
  # Run godep save and do a diff, to ensure that the version we got from
  # `godep restore` matched what was in the remote repo.
  cp Godeps/Godeps.json /tmp/Godeps.json.head
  run_and_expect_silence rm -rf Godeps/ vendor/
  run_and_expect_silence godep save ./...
  run_and_expect_silence diff \
    <(sed '/GodepVersion/d;/Comment/d;/GoVersion/d;' /tmp/Godeps.json.head) \
    <(sed '/GodepVersion/d;/Comment/d;/GoVersion/d;' Godeps/Godeps.json)
  run_and_expect_silence git diff --exit-code -- ./vendor/
fi

#
# Run errcheck, to ensure that error returns are always used.
# Note: errcheck seemingly doesn't understand ./vendor/ yet, and so will fail
# if imports are not available in $GOPATH. So, in Travis, it always needs to
# run after `godep restore`. Locally it can run anytime, assuming you have the
# packages present in #GOPATH.
#
if [[ "$RUN" =~ "errcheck" ]] ; then
  run_and_expect_silence errcheck \
    -ignore fmt:Fprintf,fmt:Fprintln,fmt:Fprint,io:Write,os:Remove,net/http:Write \
    $(go list -f '{{ .ImportPath }}' ./... | grep -v test)
fi

#
# Run ineffassign, to check for ineffectual assignments.
#
if [[ "$RUN" =~ "ineffassign" ]] ; then
  run_and_expect_silence ineffassign $(go list -f '{{ .Dir }}' ./...)
fi

# Run generate to make sure all our generated code can be re-generated with
# current tools.
# Note: Some of the tools we use seemingly don't understand ./vendor yet, and
# so will fail if imports are not available in $GOPATH. So, in travis, this
# always needs to run after `godep restore`.
if [[ "$RUN" =~ "generate" ]] ; then
  # Additionally, we need to run go install before go generate because the stringer command
  # (using in ./grpc/) checks imports, and depends on the presence of a built .a
  # file to determine an import really exists. See
  # https://golang.org/src/go/internal/gcimporter/gcimporter.go#L30
  # Without this, we get error messages like:
  #   stringer: checking package: grpc/bcodes.go:6:2: could not import
  #     github.com/letsencrypt/boulder/probs (can't find import:
  #     github.com/letsencrypt/boulder/probs)
  go install ./probs
  go install ./vendor/google.golang.org/grpc/codes
  run_and_expect_silence go generate ./...
  run_and_expect_silence git diff --exit-code $(ls | grep -v Godeps)
fi

if [[ "$RUN" =~ "rpm" ]]; then
  make rpm
fi

if [[ "$RUN" =~ "dashlint" ]]; then
  python test/grafana/lint.py
fi
