#!/usr/bin/env bash

set -eu

if type realpath >/dev/null 2>&1 ; then
  cd "$(realpath -- $(dirname -- "$0"))"
fi

# posix compliant escape sequence
esc=$'\033'"["

#
# Defaults
#
DB_NEXT_PATH="_db-next/migrations"
OUTCOME="ERROR"
PROMOTE=()
RUN=()

#
# Print Functions
#
function print_outcome() {
  if [ "$OUTCOME" == OK ]
  then
    echo -e "${esc}0;32;1m""$OUTCOME""${esc}0m"
  else
    echo -e "${esc}0;31;1m""$OUTCOME""${esc}0m"
  fi
}

function print_usage_exit() {
  echo "$USAGE"
  exit 0
}

function print_heading() {
  echo
  echo -e "${esc}0;34;1m"$1"${esc}0m"
}

function print_from() {
  echo -e "from: ${esc}0;36;1m"$1"${esc}0m"
}

function print_to() {
  echo -e "to:   ${esc}0;32;1m"$1"${esc}0m"
}

#
# CLI Helper Functions
#
function check_arg() {
  if [ -z "$OPTARG" ]
  then
    exit_msg "No arg for --$OPT option, use: -h for help">&2
  fi
}

function exit_msg() {
  # complain to STDERR and exit with error
  echo "$*" >&2
  exit 2
}

#
# Utility Functions
#
function get_migrations() {
  migrations=( $(find $DB_NEXT_PATH -mindepth 1 -maxdepth 1 -not -path '*/\.*' -type "$1"  2> /dev/null | sort) )
  if [ -z "${migrations[@]+x}" ]
  then
    echo "There are no migrations at path: "\"$DB_NEXT_PATH\"""
    exit 1
  fi
}

function print_migrations(){
  iter=1
  for mig_file in "${migrations[@]}"
  do
    echo ""$iter") $(basename -- "${mig_file}")"
    iter=$(expr "$iter" + 1)
  done
}

#
# Main CLI Parser
#
USAGE="$(cat -- <<-EOM

Usage:
Boulder DB Migrations CLI:

  Helper for listing, promoting, and demoting Boulder schema files

  ./$(basename "${0}") [OPTION]...

  -l, --list-next               Lists schemas exclusively present in sa/db-next
  -c, --list-current            Lists schemas exclusively present in sa/db
  -p, --promote                 Promotes a given schema from sa/db-next to sa/db
  -d, --demote                  Demotes a given schema from sa/db to sa/db-next
  -h, --help                    Shows this help message

EOM
)"

while getopts nchpd-: OPT; do
  if [ "$OPT" = - ]; then     # long option: reformulate OPT and OPTARG
    OPT="${OPTARG%%=*}"       # extract long option name
    OPTARG="${OPTARG#$OPT}"   # extract long option argument (may be empty)
    OPTARG="${OPTARG#=}"      # if long option argument, remove assigning `=`
  fi
  case "$OPT" in
    n | list-next )              RUN+=("list_next") ;;
    c | list-current )           RUN+=("list_current") ;;
    p | promote )                RUN+=("promote") ;;
    d | demote )                 RUN+=("demote") ;;
    h | help )                   print_usage_exit ;;
    ??* )                        exit_msg "Illegal option --$OPT" ;;  # bad long option
    ? )                          exit 2 ;;  # bad short option (error reported via getopts)
  esac
done
shift $((OPTIND-1)) # remove parsed migrations and args from $@ list

# On EXIT, trap and print outcome
trap "print_outcome" EXIT

STEP="list_next"
if [[ "${RUN[@]}" =~ "$STEP" ]] ; then
  print_heading "Next Schemas"
  get_migrations "f"
  print_migrations
fi

STEP="list_current"
if [[ "${RUN[@]}" =~ "$STEP" ]] ; then
  print_heading "Current Schemas"
  get_migrations "l"
  print_migrations
fi

STEP="promote"
if [[ "${RUN[@]}" =~ "$STEP" ]] ; then
  print_heading "Promote Schema"
  get_migrations "f"
  declare -a mig_index=()
  declare -A mig_file=()
  for i in "${!migrations[@]}"; do
    mig_index[$i]="${migrations[$i]%% *}"
    mig_file[${mig_index[$i]}]="${migrations[$i]#* }"
  done

  promote=""
  PS3='Which schema would you like to promote? (q to cancel): '
  
  select opt in "${mig_index[@]}"; do
    case "$opt" in
      "") echo "Invalid option or cancelled, exiting..." ; break ;;
      *)  promote="${mig_file[$opt]}" ; break ;;
    esac
  done
  if [ ! -z "$promote" ]
  then
    schema_name="$(basename -- "$promote")"
    promoted_path="_db/migrations/"$schema_name""

    print_heading "Promoting Schema"
    print_from "$promote"
    print_to "$promoted_path"
    mv "$promote" "$promoted_path"
    ln -s "$(realpath --relative-to="$DB_NEXT_PATH" "$promoted_path")" "$DB_NEXT_PATH"
  fi
fi

STEP="demote"
if [[ "${RUN[@]}" =~ "$STEP" ]] ; then
  print_heading "Demote Schema"
  get_migrations "l"
  declare -a mig_index=()
  declare -A mig_file=()
  for i in "${!migrations[@]}"; do
    mig_index[$i]="${migrations[$i]%% *}"
    mig_file[${mig_index[$i]}]="${migrations[$i]#* }"
  done

  demote=""
  PS3='Which schema would you like to demote? (q to cancel): '
  
  select opt in "${mig_index[@]}"; do
    case "$opt" in
      "") echo "Invalid option or cancelled, exiting..." ; break ;;
      *)  demote="${mig_file[$opt]}" ; break ;;
    esac
  done
  if [ ! -z "$demote" ]
  then
    schema_name="$(basename -- "$demote")"
    promoted_path="_db/migrations/"$schema_name""

    print_heading "Demoting Schema"
    print_from "_db/migrations/"$schema_name""
    print_to "$demote"
    rm "$demote"
    mv "$promoted_path" "$demote"
  fi
fi

OUTCOME="OK"
