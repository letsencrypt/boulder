#!/usr/bin/env bash

# -e Stops execution in the instance of a command or pipeline error.
# -u Treat unset variables as an error and exit immediately.
set -eu

STATUS="FAILURE"
RST=$(tput sgr0)
RED=$(tput bold && tput setaf 1)
GRN=$(tput bold && tput setaf 2)
BLU=$(tput bold && tput setaf 4)

function exit_msg() {
  # complain to STDERR and exit with error
  echo "${*}" >&2
  exit 2
}

function print_outcome() {
  if [ "${STATUS}" == SUCCESS ]
  then
    echo
    echo "${GRN}${STATUS}${RST}"
  else
    echo
    echo "${RED}${STATUS}${RST}"
  fi
}

function print_heading() {
  echo
  echo "${BLU}${1}${RST}"
}

function not_yes_no() {
    case "${1}" in
      [yY][eE][sS]|[yY]) create_branch="yes" && return 1 ;;
      [nN][oO]|[nN]) create_branch="no" && return 1 ;;
      *) return 0 ;;
    esac
}

function get_user_input() {
    while [ -z "${create_branch}" ]; do
        read -p "${1}" create_branch
        if not_yes_no "${create_branch}" 
        then
            echo "Need [yes/no], got [${create_branch}]"
            create_branch=""
        fi
    done
}

function check_arg() {
  if [ -z "$OPTARG" ]
  then
    exit_msg "No arg for --$OPT option, use: -h for help">&2
  fi
}

function print_usage_exit() {
  echo "$USAGE"
  exit 0
}

USAGE="$(cat -- <<-EOM

Usage:

Without no options passed, this tool will execute a regular tag and release.

  -f, --hotfix                        Executes release as a hotfix.
  -c, --cherry-pick '<sha> <sha>...'  Each commit SHA will be cherry-picked, in the
                                      order passed (only used with '--hotfix')
  -h, --help                          Shows this help message

EOM
)"

RUN=()
COMMITS=()
while getopts hfc:-: OPT; do
  if [ "$OPT" = - ]; then     # long option: reformulate OPT and OPTARG
    OPT="${OPTARG%%=*}"       # extract long option name
    OPTARG="${OPTARG#$OPT}"   # extract long option argument (may be empty)
    OPTARG="${OPTARG#=}"      # if long option argument, remove assigning `=`
  fi
  case "$OPT" in
    f | hotfix      )  RUN+=("hotfix") ;;
    c | cherry-pick )  check_arg; COMMITS+=(${OPTARG[@]}) ;; # multiargs have spaces, leave this unquoted 
    h | help        )  print_usage_exit ;;
    ??*             )    exit_msg "Illegal option --$OPT" ;;  # bad long option
    ?               )           exit 2 ;;  # bad short option (error reported via getopts)
  esac
done
shift $((OPTIND-1)) # remove parsed options and args from $@ list

# Validate use of --cherry-pick is valid.
if ! [[ "${RUN[@]}" =~ hotfix ]]
then
  exit_msg "Illegal option: (-c, --cherry-pick) without (-f, --hotfix)"
fi
exit

# On EXIT, trap and print outcome.
trap "print_outcome" EXIT

print_heading "Ensuring main branch is up to date"
git fetch --all
git checkout origin/main

print_heading "Fetching details for the most recent release tag"
latest_tag_sha=$(git ls-remote --refs --tags | tail -1 | awk '{print $1}')
latest_tag_name=$(git ls-remote --refs --tags | tail -1 | awk '{print $2}' | sed 's|refs\/tags\/||')

print_heading "Latest tag:"
echo "${latest_tag_name}"
echo "${latest_tag_sha}"


print_heading "Hotfix release tag:"
if [[ "${latest_tag_name: -1}" =~ ^[0-9] ]]
then
    new_tag_name="${latest_tag_name}a"
else
    next_tag_letter=$(echo "${latest_tag_name: -1}" |  tr "0-9a-z" "1-9a-z_")
    tag_with_last_char_removed=$(echo "${latest_tag_name}" | sed 's|.$||')
    new_tag_name="${tag_with_last_char_removed}${next_tag_letter}"   
fi
echo "${new_tag_name}"

local create_branch
release_branch_name=$(echo "${new_tag_name}" | sed 's|release-|release-branch-|')
get_user_input "Create hotfix release branch: ${release_branch_name}? "
if [ "${create_branch}" = yes ]
then
    print_heading "Creating new branch ${release_branch_name} @ ${latest_tag_sha}"
    git checkout -b "${release_branch_name}" "${latest_tag_sha}"
    git push --set-upstream origin "${release_branch_name}"

    cherry_pick_sha=""
    while [ -z "${cherry_pick_sha}" ]; do
        read -p "Commit to cherry pick: " cherry_pick_sha
        print_heading "Cherry-picking ${cherry_pick_sha} to branch ${release_branch_name}"
        git cherry-pick "${cherry_pick_sha}"
        git push origin ${release_branch_name}:${release_branch_name}
        git tag "${new_tag_name}" -s -m "${new_tag_name}" "origin/${release_branch_name}"
    done

    print_heading "Complete the following steps:"
    echo "- Diff: https://github.com/letsencrypt/boulder/compare/${latest_tag_name}...${release_branch_name}"
    echo "- Open https://github.com/letsencrypt/boulder/actions/workflows/boulder-ci.yml"
    echo "- Ensure that the CI pass for ${release_branch_name} completes successfully"
    echo "- Run: git push origin ${new_tag_name}"
else
  exit_msg "No hotfix release branch was created, exiting..."
fi

# Because set -e stops execution in the instance of a command or pipeline error;
# if we got here we assume success
STATUS="SUCCESS"
