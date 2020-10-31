#!/usr/bin/env bash

# Catch any non-flagged use
if [ $# -eq 0 ]; then
    echo "Invalid: "$(basename "$0")" has required flags, use: -h for help"
    exit 1
fi

# e: Stops execution in the instance of a command or pipeline error
# u: Treat unset variables as an error and exit immediately
set -eu

# Defaults
STATUS="FAILURE"
USAGE=""
OPTARG=""

function print_outcome() {
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

USAGE="$(cat -- <<-EOM
Usage:
    -h             Displays this help message
    -a             Run all lint, unit, and integration tests

Commands:
    unit           Unit tests subcommand, run unit -h for more information
    integration    Integration tests subcommand, run integration -h for more information
EOM
)"

while getopts ":ha" opt; do # Parse options to the `test_cmd` command
  case "${opt}" in
    h) 
      print_usage_exit
      ;;
    a)
      trap_outcome_on_exit
      docker-compose run --use-aliases boulder ./test.sh
      ;;
    *)
      print_invalid_option_exit
      ;;
  esac
done

if [ $# -gt 1 ] # Check for subcommands
then
  shift "$((OPTIND -1))"
  subcommand="${1}" && shift

USAGE="$(cat -- <<-EOM
Usage:"
    -h                Displays this help message
    -a                Run all unit tests
    -d <DIRECTORY>    Run unit tests for a specific directory
EOM
)"

  case "$subcommand" in
  unit) # Parse options to the unit sub command
    while getopts ":d:ha" opt; do
      case "${opt}" in
        h) 
          print_usage_exit
          ;;
        a)
          trap_outcome_on_exit
          docker-compose run --use-aliases boulder go test -p 1 ./...
          ;;
        d)
          trap_outcome_on_exit
          docker-compose run --use-aliases boulder go test "$OPTARG"
          ;;
        :) # <DIRECTORY>
          print_invalid_option_missing_argument_exit
          ;;
        *)
          print_invalid_option_exit
          ;;
      esac
    done
    shift "$((OPTIND -1))"
    ;;
esac

USAGE="$(cat -- <<-EOM
Usage:"
    -h                   Displays this help message"
    -a                   Run all integration tests"
    -l                   List of available integration tests"
    -f <FILTER_REGEX>    Run only those tests and examples matching the regular expression"

                         Note:"
                         This option disables the '"back in time"' integration test setup"

                         For tests, the regular expression is split by unbracketed slash (/)"
                         characters into a sequence of regular expressions"

                         Example:"
                         ./"$(basename -- "$0")" integration -f TestAkamaiPurgerDrainQueueFails/TestWFECORS"
EOM
)"

case "$subcommand" in
  integration) # Parse options to the integration sub command
    while getopts ":f:lha" opt; do
      case "${opt}" in
        h)
          print_usage_exit
          ;;
        a)
          trap_outcome_on_exit
          docker-compose run --use-aliases boulder python3 test/integration-test.py --chisel --gotest
          ;;
        l)
          print_list_of_integration_tests
          ;;
        f)
          trap_outcome_on_exit
          docker-compose run --use-aliases boulder python3 test/integration-test.py --chisel --gotest --filter "$OPTARG"
          ;;
        :) # <FILTER_REGEX>
          print_invalid_option_missing_argument_exit
          ;;
        *)
          print_invalid_option_exit
          ;;
      esac
    done
    shift "$((OPTIND -1))"
    ;;
esac
fi
# set -e stops execution in the instance of a command or pipeline error; if we got here we assume success
STATUS="SUCCESS"
