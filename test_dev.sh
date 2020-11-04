#!/usr/bin/env bash

# Run all tests and coverage checks. Called from Travis automatically, also
# suitable to run manually. See list of prerequisite packages in .travis.yml
if type realpath >/dev/null 2>&1 ; then
  cd "$(realpath -- $(dirname -- "$0"))"
fi

#
# Defaults
#
STATUS="FAILURE"
USAGE=""
OPTARG=""
UNIT_FILTER=("-p" "1" "./...")
INT_FILTER=()
TRAVIS="${TRAVIS:-false}"
BOULDER_CONFIG_DIR="test/config"

# -e Stops execution in the instance of a command or pipeline error
# -u Treat unset variables as an error and exit immediately
set -eu

#
# Print Functions
#
function print_outcome() {
  if [ "$STATUS" == SUCCESS ]
  then
    echo -e "\e[32m"$STATUS"\e[0m"
  else
    echo -e "\e[31m"$STATUS"\e[0m"
  fi
}

function print_list_of_integration_tests() {
  for file in ./test/integration/*.go; do
    [ -e "$file" ] || continue
    cat "$file" | grep -e '^func Test' | awk '{print $2}' | sed s/\(t//
  done
  exit 0
}

function exit_msg() { echo "$*" >&2; exit 2; }  # complain to STDERR and exit with error
function check_arg() { if [ -z "$OPTARG" ]; then exit_msg "No arg for --$OPT option, use: -h for help">&2; fi; }
function trap_outcome_on_exit() { trap "print_outcome" EXIT; }
function print_usage_exit() { echo "$USAGE"; exit 0; }
function print_heading { echo; echo -e "\e[34m\e[1m"$1"\e[0m"; }

#
# Main CLI Parser
#
USAGE="$(cat -- <<-EOM

Usage: "$(basename "$0")" [OPTION]...
Boulder test suite CLI

With no options passed: runs standard battery of tests (lint, unit, and integation)

    -n, --config-next                          Sets BOULDER_CONFIG_DIR from test/config to test/config-next
    -d, --unit-test-filter        <DIRECTORY>  Run unit tests for a specific boulder component directory
    -s, --show-integration-tests               List available integration tests
    -f, --integration-test-filter <REGEX>      Run only those tests and examples matching the regular expression

                                               Note:
                                                This option disables the '"back in time"' integration test setup

                                                For tests, the regular expression is split by unbracketed slash (/)
                                                characters into a sequence of regular expressions

                                               Example:
                                                TestAkamaiPurgerDrainQueueFails/TestWFECORS
EOM
)"

while getopts luecispvgmnhd:f:-: OPT; do
  if [ "$OPT" = - ]; then   # long option: reformulate OPT and OPTARG
    OPT="${OPTARG%%=*}"       # extract long option name
    OPTARG="${OPTARG#$OPT}"   # extract long option argument (may be empty)
    OPTARG="${OPTARG#=}"      # if long option argument, remove assigning `=`
  fi
  case "$OPT" in
    l | lints )                  RUN+=("lints") ;;
    u | unit )                   RUN+=("unit") ;;
    d | unit-dir-filter )        check_arg; UNIT_FILTER=(); UNIT_FILTER+=("${OPTARG}") ;;
    e | enable-race-detector )   TRAVIS="true" ;;
    c | coverage )               RUN+=("coverage") ;;
    i | integration )            RUN+=("integration") ;;
    s | show-integration-tests ) print_list_of_integration_tests ;;
    f | integration-filter )     check_arg; INT_FILTER+=("--filter" "${OPTARG}") ;;
    p | start )                  RUN+=("start") ;;
    v | gomod-vendor )           RUN+=("gomod-vendor") ;;
    g | generate )               RUN+=("generate") ;;
    m | rpm )                    RUN+=("rpm") ;;
    n | conf-next )              BOULDER_CONFIG_DIR="test/config-next" ;;
    h | help )                   print_usage_exit ;;
    ??* )                        exit_msg "Illegal option --$OPT" ;;  # bad long option
    ? )                          exit 2 ;;  # bad short option (error reported via getopts)
  esac
done
shift $((OPTIND-1)) # remove parsed options and args from $@ list

print_heading "Boulder Test Suite CLI"
print_heading "Settings:"
trap_outcome_on_exit

# The list of segments to run. To run only some of these segments, pre-set the
# RUN variable with the ones you want (see .travis.yml for an example).
# Order doesn't matter. Note: gomod-vendor is specifically left out of the
# defaults, because we don't want to run it locally (it could delete local
# state) We also omit coverage by default on local runs because it generates
# artifacts on disk that aren't needed.
RUN=${RUN:-("lints" "unit" "integration")}

settings="$(cat -- <<-EOM
    RUN:                ${RUN[@]}
    BOULDER_CONFIG_DIR: $BOULDER_CONFIG_DIR
    UNIT_FILTER:        ${UNIT_FILTER[@]}
    TRAVIS:             $TRAVIS
    INT_FILTER:         ${INT_FILTER[@]}

EOM
)"
echo "$settings"
print_heading "Starting"

function run_and_expect_silence() {
  echo "$@"
  result_file=$(mktemp -t bouldertestXXXX)
  "$@" 2>&1 | tee "${result_file}"

  # Fail if result_file is nonempty.
  if [ -s "${result_file}" ]; then
    rm "${result_file}"
    exit 1
  fi
  rm "${result_file}"
}

function run_unit_tests() {
  if [ "${TRAVIS}" == true ]; then
    # Run the full suite of tests once with the -race flag. Since this isn't
    # running tests individually we can't collect coverage information.
    go test -race "${UNIT_FILTER[@]}"
  else
    # When running locally, we skip the -race flag for speedier test runs. We
    # also pass -p 1 to require the tests to run serially instead of in
    # parallel. This is because our unittests depend on mutating a database and
    # then cleaning up after themselves. If they run in parallel, they can fail
    # spuriously because one test is modifying a table (especially
    # registrations) while another test is reading it.
    # https://github.com/letsencrypt/boulder/issues/1499
    go test "${UNIT_FILTER[@]}"
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
  goveralls -v -coverprofile=gover.coverprofile -service=travis-pro
}

#
# Run various linters.
#
if [[ "${RUN[@]}" =~ lints ]] ; then
  print_heading "Running Lints"
  # golangci-lint is sometimes slow. Travis will kill our job if it goes 10m
  # without emitting logs, so set the timeout to 9m.
  golangci-lint run --timeout 9m ./...
  run_and_expect_silence ./test/test-no-outdated-migrations.sh
  python test/grafana/lint.py
  # Check for common spelling errors using codespell.
  # Update .codespell.ignore.txt if you find false positives (NOTE: ignored
  # words should be all lowercase).
  run_and_expect_silence codespell \
    --ignore-words=.codespell.ignore.txt \
    --skip=.git,.gocache,go.sum,go.mod,vendor,bin,*.pyc,*.pem,*.der,*.resp,*.req,*.csr,.codespell.ignore.txt,.*.swp
fi

#
# Unit Tests.
#
print_heading "Running Unit Tests"
if [[ "${RUN[@]}" =~ unit ]] ; then
  run_unit_tests
fi

#
# Unit Test Coverage.
#
print_heading "Running Unit Coverage"
if [[ "${RUN[@]}" =~ coverage ]] ; then
  run_test_coverage
fi

#
# Integration tests
#
print_heading "Running Integration Tests"
if [[ "${RUN[@]}" =~ integration ]] ; then
  python3 test/integration-test.py --chisel --gotest "${INT_FILTER[@]}"
fi

# Test that just ./start.py works, which is a proxy for testing that
# `docker-compose up` works, since that just runs start.py (via entrypoint.sh).
if [[ "${RUN[@]}" =~ start ]] ; then
  print_heading "Running Start Test"
  python3 start.py &
  for I in $(seq 1 100); do
    sleep 1
    curl http://localhost:4000/directory && break
  done
  if [[ "$I" = 100 ]]; then
    echo "Boulder did not come up after ./start.py."
    exit 1
  fi
fi

# Run go mod vendor (happens only in Travis) to check that the versions in
# vendor/ really exist in the remote repo and match what we have.
if [[ "${RUN[@]}" =~ gomod-vendor ]] ; then
  print_heading "Running Go Mod Vendor"
  go mod vendor
  git diff --exit-code
fi

# Run generate to make sure all our generated code can be re-generated with
# current tools.
# Note: Some of the tools we use seemingly don't understand ./vendor yet, and
# so will fail if imports are not available in $GOPATH.
if [[ "${RUN[@]}" =~ generate ]] ; then
  print_heading "Running Generate"
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
  run_and_expect_silence git diff --exit-code .
fi

if [[ "${RUN[@]}" =~ rpm ]]; then
  print_heading "Running RPM"
  make rpm
fi

# set -e stops execution in the instance of a command or pipeline error; if we got here we assume success
STATUS="SUCCESS"
