#!/usr/bin/env bash

# Catch any non-flagged use
if [ $# -eq 0 ]; then
    echo "Invalid: $(basename "$0") has required flags, use: -h for help"
    exit 1
fi

# e: Stops execution in the instance of a command or pipeline error
# u: Treat unset variables as an error and exit immediately
set -eu

# Default to FAILURE
STATUS="FAILURE"

function print_outcome {
  if [ $STATUS == "SUCCESS" ]
  then
    echo -e "\e[32m$STATUS\e[0m"
  else
    echo -e "\e[31m$STATUS\e[0m"
  fi
}

while getopts ":ha" opt; do # Parse options to the `test_cmd` command
  case ${opt} in
    h)
      echo
      echo "Usage:"
      echo "    -h             Displays this help message"
      echo "    -a             Run all lint, unit, and integration tests"
      echo
      echo "Commands:"
      echo "    unit           Unit tests subcommand, run unit -h for more information"
      echo "    integration    Integration tests subcommand, run integration -h for more information"
      exit 0
      ;;
    a) # -a (all)
      trap "print_outcome" EXIT
      docker-compose run --use-aliases boulder ./test.sh
      ;;
    *) # catch invalid options
      echo "Invalid Option: $OPTARG use: -h for help" 1>&2
      exit 1
      ;;
  esac
done

if [ $# -gt 1 ] # Check for subcommands
then
  shift $((OPTIND -1))
  subcommand="${1}"; shift

  case "$subcommand" in
  unit) # Parse options to the unit sub command
    while getopts ":d:ha" opt; do
      case ${opt} in
        h) # -h (help)
          echo
          echo "Usage:"
          echo "    -h                Displays this help message"
          echo "    -a                Run all unit tests"
          echo "    -d <DIRECTORY>    Run unit tests for a specific directory"
          exit 0
          ;;
        a)  # -a (all)
          trap "print_outcome" EXIT
          docker-compose run --use-aliases boulder go test -p 1 ./...
          ;;
        d) # -d (directory)
          trap "print_outcome" EXIT
          docker-compose run --use-aliases boulder go test $OPTARG
          ;;
        :) # assigns $OPTARG for -d
          echo "Invalid Option: $OPTARG requires an argument, use: -h for help" 1>&2
          exit 1
          ;;
        *) # catch invalid options
          echo "Invalid Option: $OPTARG use: -h for help" 1>&2
          exit 1
          ;;
      esac
    done
    shift $((OPTIND -1))
    ;;
esac

case "$subcommand" in
  integration) # Parse options to the integration sub command
    while getopts ":f:lha" opt; do
      case ${opt} in
        h) # -h (help)
          echo
          echo "Usage:"
          echo "    -h                   Displays this help message"
          echo "    -a                   Run all integration tests"
          echo "    -l                   List of available integration tests"
          echo "    -f <FILTER_REGEX>    Run only those tests and examples matching the regular expression"
          echo
          echo "                         Note:"
          echo "                         This option disables the '"back in time"' integration test setup"
          echo
          echo "                         For tests, the regular expression is split by unbracketed slash (/)"
          echo "                         characters into a sequence of regular expressions"
          echo
          echo "                         Example:"
          echo "                         ./$(basename "$0") integration -f TestAkamaiPurgerDrainQueueFails/TestWFECORS"
          exit 0
          ;;
        a)
          trap "print_outcome" EXIT
          docker-compose run --use-aliases boulder python3 test/integration-test.py --chisel --gotest
          ;;
        l) # -l (list)
          for file in ./test/integration/*.go
            do cat $file | grep -e '^func Test' | awk '{print $2}' | sed s/\(t//
          done
          ;;
        f) # -f (filter)
          trap "print_outcome" EXIT
          docker-compose run --use-aliases boulder python3 test/integration-test.py --chisel --gotest --filter "$OPTARG"
          ;;
        :) # assigns $OPTARG for -f
          echo "Invalid Option: $OPTARG requires an argument, use: -h for help" 1>&2
          exit 1
          ;;
        *) # catch invalid options
          echo "Invalid Option: $OPTARG use: -h for help" 1>&2
          exit 1
          ;;
      esac
    done
    shift $((OPTIND -1))
    ;;
esac
fi
# set -e stops execution in the instance of a command or pipeline error; if we got here we assume success
STATUS="SUCCESS"
