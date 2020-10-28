#!/usr/bin/env bash

function outcome_and_exit {
  if [ $1 -eq 0 ]
  then
    passed
  else
    failed
    exit $1
  fi
}

function failed {
  echo -e "\e[31mFAILED$1\e[0m"
}

function passed {
  echo -e "\e[32mPASSED$1\e[0m"
}

while getopts ":ha" opt; do # Parse options to the `test_cmd` command
  case ${opt} in
    h ) # -h (help)
      echo "Usage:"
      echo "    -h             Displays this help message"
      echo "    -a             Perform all unit and integration tests"
      echo
      echo "Commands:"
      echo "    unit           Unit tests subcommand, run unit -h for more information"
      echo "    integration    Integration tests subcommand, run integration -h for more information"
      exit 0
      ;;
    a ) # -a (all)
      docker-compose run --use-aliases boulder ./test.sh
      outcome_and_exit $?
      ;;
   \? ) # catch invalid options
      echo "Invalid Option: $OPTARG use: -h for help" 1>&2
      exit 1
      ;;
  esac
done
shift $((OPTIND -1))
subcommand=$1; shift

case "$subcommand" in
  unit) # Parse options to the unit sub command
    while getopts ":d:ha" opt; do
      case ${opt} in
        h ) # -h (help)
          echo "Usage:"
          echo "    -h                Displays this help message"
          echo "    -a                Perform all unit tests"
          echo "    -d <directory>    Perform unit tests for a specific directory"
          exit 0
          ;;
        a )  # -a (all)
          docker-compose run -e RUN="unit" --use-aliases boulder ./test.sh
          outcome_and_exit $?
          ;;
        d ) # -d (directory)
          docker-compose run --use-aliases boulder go test $OPTARG
          outcome_and_exit $?
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
          echo "Usage:"
          echo "    -h                   Displays this help message"
          echo "    -a                   Perform all integration tests"
          echo "    -s <FILTER_REGEX>    Perform a subset of integration tests that match a given python regex,"
          echo "                         this option disables the '"back in time"' integration test"
          echo
          echo "List of integration tests:"
          for file in ./test/integration/*.go
            do cat $file | grep -e "^func" | grep " *testing" | awk '{print $2}' | sed s/\(t// | awk '{print "    " $1}'
          done
          exit 0
          ;;
        a )
          docker-compose run -e RUN="integration" --use-aliases boulder ./test.sh
          outcome_and_exit $?
          ;;
        s ) # -s (subset)
          docker-compose run -e RUN="integration" -e INT_FILTER="$OPTARG" --use-aliases boulder ./test.sh
          outcome_and_exit $?
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