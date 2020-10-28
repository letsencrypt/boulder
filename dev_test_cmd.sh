#!/usr/bin/env bash

# Catch any non-flagged use
if [ $# -eq 0 ]; then
    echo "Invalid: $(basename "$0") has required flags, use: -h for help"
    exit 1
fi

# e: Stops execution in the instance of a command or pipeline error
# u: Treat unset variables as an error and exit immediately
set -eu

# Default to FAILED
STATUS="FAILED"

function outcome_and_exit {
  if [ $STATUS == "SUCCESS" ]
  then
    echo -e "\e[32m$STATUS\e[0m"
  else
    echo -e "\e[31m$STATUS\e[0m"
  fi
}

while getopts ":ha" opt; do # Parse options to the `test_cmd` command
  case ${opt} in
    h )
      echo
      echo "Usage:"
      echo "    -h             Displays this help message"
      echo "    -a             Run all unit and integration tests"
      echo
      echo "Commands:"
      echo "    unit           Unit tests subcommand, run unit -h for more information"
      echo "    integration    Integration tests subcommand, run integration -h for more information"
      exit 0
      ;;
    a ) # -a (all)
      docker-compose run --use-aliases boulder ./test.sh
      ;;
   \? ) # catch invalid options
      echo "Invalid Option: $OPTARG use: -h for help" 1>&2
      exit 1
      ;;
  esac
done
shift $((OPTIND -1))
subcommand=$1; shift

# Catch any non-flagged subcommand usage
if [ $# -eq 0 ]; then
    echo "Invalid: $(basename "$0") <COMMAND> has required flags, use: -h for help"
    exit 1
fi

case "$subcommand" in
  unit) # Parse options to the unit sub command
    while getopts ":d:ha" opt; do
      case ${opt} in
        h ) # -h (help)
          echo
          echo "Usage:"
          echo "    -h                Displays this help message"
          echo "    -a                Run all unit tests"
          echo "    -d <DIRECTORY>    Run unit tests for a specific directory"
          STATUS="HELP"
          exit 0
          ;;
        a )  # -a (all)
          trap "outcome_and_exit" EXIT 
          docker-compose run -e RUN="unit" --use-aliases boulder ./test.sh
          ;;
        d ) # -d (directory)
          trap "outcome_and_exit" EXIT 
          docker-compose run --use-aliases boulder go test $OPTARG
          ;;
       \? ) # catch invalid options
          echo "Invalid Option: $OPTARG use: -h for help" 1>&2
          exit 1
          ;;
        : ) # assigns $OPTARG for -d
          echo "Invalid Option: $OPTARG requires an argument, use: -h for help" 1>&2
          exit 1
          ;;
      esac
    done
    shift $((OPTIND -1))
    ;;
esac

case "$subcommand" in
  integration) # Parse options to the integration sub command
    while getopts ":s:ha" opt; do
      case ${opt} in
        h ) # -h (help)
          echo
          echo "Usage:"
          echo "    -h                   Displays this help message"
          echo "    -a                   Run all integration tests"
          echo "    -f <FILTER_REGEX>    Run only those tests and examples matching the regular expression."
          echo "                         For tests, the regular expression is split by unbracketed slash (/)"
          echo "                         characters into a sequence of regular expressions, and each part"
          echo "                         of a test's identifier must match the corresponding element in"
          echo "                         the sequence, if any. Note that possible parents of matches are"
          echo "                         run too, so that -f X/Y matches and runs and reports the result"
          echo "                         of all tests matching X, even those without sub-tests matching Y,"
          echo "                         because it must run them to look for those sub-tests. Note: this"
          echo "                         this option disables the '"back in time"' integration test"
          echo
          echo "List of integration tests:"
          for file in ./test/integration/*.go
            do cat $file | grep -e '^func Test' | awk '{print $2}' | sed s/\(t// | awk '{print "    " $1}'
          done
          exit 0
          ;;
        a )
          trap "outcome_and_exit" EXIT 
          docker-compose run --use-aliases boulder python3 test/integration-test.py --chisel --gotest
          ;;
        f ) # -f (filter)
          trap "outcome_and_exit" EXIT 
          docker-compose run --use-aliases boulder python3 test/integration-test.py --chisel --gotest --filter "$OPTARG"
          ;;
       \? ) # catch invalid options
          echo "Invalid Option: $OPTARG use: -h for help" 1>&2
          exit 1
          ;;
        : ) # assigns $OPTARG for -s
          echo "Invalid Option: $OPTARG requires an argument, use: -h for help" 1>&2
          exit 1
          ;;
      esac
    done
    shift $((OPTIND -1))
    ;;
esac

# set -e stops execution in the instance of a command or pipeline error; if we got here we assume success
STATUS="SUCCESS"