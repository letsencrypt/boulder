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
UNIT_FILTER="-p 1 ./..."
INTEGRATION_ARGS=()
TRAVIS="${TRAVIS:-false}"
BOULDER_CONFIG_DIR="test/config"

# -e Stops execution in the instance of a command or pipeline error
# -u Treat unset variables as an error and exit immediately
set -eu

#
# Print Functions
#
function print_outcome() {
  print_set_reset
  if [ "$STATUS" == SUCCESS ]
  then
    echo -e "\e[32m"$STATUS"\e[0m"
  else
    echo -e "\e[31m"$STATUS"\e[0m"
  fi
}

function trap_outcome_on_exit() {
  trap "print_outcome" EXIT
}

function print_usage_exit() {
  echo "$USAGE" 1>&2
  exit 0
}

function print_invalid_option_missing_argument_exit() {
  echo "Invalid Option: $OPTARG requires an argument, use: -h for help" 1>&2
  exit 1
}

function print_invalid_option_exit() {
  echo "Invalid Option: $OPTARG use: -h for help" 1>&2
  exit 1
}

function print_list_of_integration_tests() {
  for file in ./test/integration/*.go; do
    [ -e "$file" ] || continue
    cat "$file" | grep -e '^func Test' | awk '{print $2}' | sed s/\(t//
  done
  exit 0
}

function print_heading {
  echo
  echo -e "\e[34m\e[1m"$1"\e[0m"
}

function print_set_dim {
  echo -e "\e[2m"
}

function print_set_reset {
  echo -e "\e[0m"
}

#
# Helper Functions
#
function run_and_expect_silence() {
  echo "$@"
  result_file="$(mktemp -t bouldertestXXXX)"
  "$@" 2>&1 | tee "${result_file}"

  # Fail if result_file is nonempty.
  if [ -s "${result_file}" ]; then
    rm "${result_file}"
    exit 1
  fi
  rm "${result_file}"
}

#
# Test Functions
#
function run_standard_test_battery() {
  trap_outcome_on_exit
  print_heading "Performing: Lint, Unit Tests, Integration Tests"
  run_lint_tests
  run_unit_tests
  run_integration_tests
}

function run_lint_tests() {
  # golangci-lint is sometimes slow. Travis will kill our job if it goes 10m
  # without emitting logs, so set the timeout to 9m.
  print_heading "Running Lint Test"
  golangci-lint run --timeout 9m ./...
  run_and_expect_silence ./test/test-no-outdated-migrations.sh
  python test/grafana/lint.py
  # Check for common spelling errors using codespell.
  # Update .codespell.ignore.txt if you find false positives (NOTE: ignored
  # words should be all lowercase).
   run_and_expect_silence codespell \
    --ignore-words=.codespell.ignore.txt \
    --skip=.git,.gocache,go.sum,go.mod,vendor,bin,*.pyc,*.pem,*.der,*.resp,*.req,*.csr,.codespell.ignore.txt,.*.swp
}

function run_coverage_tests() {
  # Run each test by itself for Travis, so we can get coverage. We skip using
  # the -race flag here because we have already done a full test run with
  # -race in `run_unit_tests` and it adds substantial overhead to run every
  # test with -race independently
  print_heading "Running Coverage Tests"
  print_set_dim
  echo "running test suite with coverage enabled and without race detection"
  go test -p 1 -cover -coverprofile="${dir}.coverprofile ./..."

  # Gather all the coverprofiles
  gover

  # We don't use the run function here because sometimes goveralls fails to
  # contact the server and exits with non-zero status, but we don't want to
  # treat that as a failure.
  goveralls -v -coverprofile=gover.coverprofile -service=travis-pro
  print_set_reset
}

function run_unit_tests() {
  print_heading "Running Unit Tests"
  print_heading "with args: ${UNIT_FILTER:-none}"
  print_set_dim
  if [ "${TRAVIS}" == true ]; then
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
    go test ${UNIT_FILTER}
  fi
  print_set_reset
}

function run_integration_tests() {
  print_heading "Running Integration Tests"
  print_heading "with args: ${INTEGRATION_ARGS[*]:-none}"
  print_set_dim
  python3 test/integration-test.py --chisel --gotest "${INTEGRATION_ARGS[@]}"
  print_set_reset
}

function run_start_test() {
  # Test that just ./start.py works, which is a proxy for testing that
  # `docker-compose up` works, since that just runs start.py (via entrypoint.sh)
  print_heading "Running Start Test"
  print_set_dim
  python3 start.py &
  for I in $(seq 1 100); do
    sleep 1
    curl http://localhost:4000/directory && break
  done
  if [[ $I = 100 ]]; then
    echo "Boulder did not come up after ./start.py."
    exit 1
  fi
  print_set_reset
}

function run_gomod_vendor() {
  # Run go mod vendor (happens only in Travis) to check that the versions in
  # vendor/ really exist in the remote repo and match what we have.
  print_heading "Running Mod Vendor"
  print_set_dim
  go mod vendor
  git diff --exit-code
  print_set_reset
}

# Run generate to make sure all our generated code can be re-generated with
# current tools.
# Note: Some of the tools we use seemingly don't understand ./vendor yet, and
# so will fail if imports are not available in $GOPATH.
function run_generate() {
  # Additionally, we need to run go install before go generate because the stringer command
  # (using in ./grpc/) checks imports, and depends on the presence of a built .a
  # file to determine an import really exists. See
  # https://golang.org/src/go/internal/gcimporter/gcimporter.go#L30
  # Without this, we get error messages like:
  #   stringer: checking package: grpc/bcodes.go:6:2: could not import
  #     github.com/letsencrypt/boulder/probs (can't find import:
  #     github.com/letsencrypt/boulder/probs)
  print_heading "Running Generate"
  print_set_dim
  go install ./probs
  go install ./vendor/google.golang.org/grpc/codes
  run_and_expect_silence go generate ./...
  run_and_expect_silence git diff --exit-code .
  print_set_reset
}

function run_rpm() {
  print_heading "Running RPM"
  make rpm
  print_set_reset
}
  

#
# Main CLI Parser
#
print_heading "Starting Boulder Test Wrapper..."

USAGE="$(cat -- <<-EOM

Usage: "$(basename "$0")" [OPTION]...
Boulder test suite runner

    -a    Runs standard battery of tests (lint, unit, and integations)
    -h    Displays this help message
    -c    Sets BOULDER_CONFIG_DIR from test/config to test/config-next

Commands:
    unit           Unit tests subcommand, run unit -h for more information
    integration    Integration tests subcommand, run integration -h for more information
EOM
)"
while getopts ":hca" opt; do
  case "${opt}" in
    a) run_standard_test_battery ;;
    h) print_usage_exit ;;
    c) BOULDER_CONFIG_DIR="test/config-next" ;;
    *) print_invalid_option_exit ;;
  esac
done

if [ $# -gt 1 ]
then
  shift "$((OPTIND -1))"
  subcommand="${1}"; shift

#
# Unit Subcommand Parser
#
USAGE="$(cat -- <<-EOM

Usage: Usage: "$(basename "$0") $subcommand" [OPTION]...
Run unit tests

If no options are supplied, will run all unit tests

    -h                Displays this help message
    -c                Sets BOULDER_CONFIG_DIR to test/config-next (default: test/config)
    -d <DIRECTORY>    Run unit tests for a specific directory
EOM
)"
case "$subcommand" in
  unit)
    while getopts ":d:hc" opt; do
      case "${opt}" in
        h) print_usage_exit ;;
        d) UNIT_FILTER="${OPTARG}" ;;
        c) BOULDER_CONFIG_DIR="test/config-next" ;;
        :) print_invalid_option_missing_argument_exit ;; # <DIRECTORY>
        *) print_invalid_option_exit ;;
      esac
    done
    trap_outcome_on_exit
    run_unit_tests
    shift "$((OPTIND -1))"
    ;;
esac

#
# Integration Subcommand Parser
#
USAGE="$(cat -- <<-EOM

Usage:
    -h                   Displays this help message
    -l                   List of available integration tests
    -c                   Sets BOULDER_CONFIG_DIR from test/config to test/config-next
    -f <FILTER_REGEX>    Run only those tests and examples matching the regular expression

                         Note:
                           This option disables the '"back in time"' integration test setup

                           For tests, the regular expression is split by unbracketed slash (/)
                           characters into a sequence of regular expressions

                         Example:
                           ./"$(basename -- "$0")" integration -f TestAkamaiPurgerDrainQueueFails/TestWFECORS
EOM
)"
case "$subcommand" in
  integration) # Parse options to the integration sub command
    while getopts ":f:lhc" opt; do
      case "${opt}" in
        h) print_usage_exit ;;
        l) print_list_of_integration_tests ;;
        f) INTEGRATION_ARGS+=("--filter" "${OPTARG}") ;;
        c) BOULDER_CONFIG_DIR="test/config-next" ;;
        :) print_invalid_option_missing_argument_exit ;; # <FILTER_REGEX>
        *) print_invalid_option_exit ;;
      esac
    done
    trap_outcome_on_exit
    run_integration_tests
    shift "$((OPTIND -1))"
    ;;
esac

fi

# set -e stops execution in the instance of a command or pipeline error; if we got here we assume success
STATUS="SUCCESS"
