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

# On EXIT, trap and print outcome.
trap "print_outcome" EXIT

print_heading "Ensuring main branch is up to date"
git fetch --all
git checkout main
git pull --rebase

print_heading "Fetching details for the most recent release tag"
latest_tag_sha=$(git show-ref --tags | tail -1 | awk '{print $1}')
latest_tag_name=$(git show-ref --tags | tail -1 | awk '{print $2}' | sed 's|refs\/tags\/||')

print_heading "Latest tag:"
echo "${latest_tag_name}"
echo "${latest_tag_sha}"


print_heading "Hotfix release tag:"
if [[ "${latest_tag_name: -1}" =~ ^[0-9] ]]
then
    new_tag_name="${latest_tag_name}a"
else
    tag_with_last_char_removed=$(echo "${latest_tag_name}" | sed 's|.$||')
    next_tag_letter=$(echo "${latest_tag_name: -1}" |  tr "0-9a-z" "1-9a-z_")
    new_tag_name="${tag_with_last_char_removed}${next_tag_letter}"   
fi
echo "${new_tag_name}"

create_branch=""
get_user_input "Create hotfix release branch: ${new_tag_name}? "
if [ "${create_branch}" = yes ]
then
    print_heading "Creating new branch ${new_tag_name} @ ${latest_tag_sha}"
    git checkout -b "${new_tag_name}" "${latest_tag_sha}"
    git push --set-upstream origin "${new_tag_name}"

    cherry_pick_sha=""
    while [ -z "${cherry_pick_sha}" ]; do
        read -p "Commit to cherry pick: " cherry_pick_sha
        print_heading "Cherry-picking ${cherry_pick_sha} to branch ${new_tag_name}"
        git cherry-pick "${cherry_pick_sha}"
        git push --force-with-lease
        git tag "${new_tag_name}" -s -m "${new_tag_name}" "origin/${new_tag_name}"
    done

    print_heading "Complete the following steps:"
    echo "- Open https://github.com/letsencrypt/boulder/actions/workflows/boulder-ci.yml"
    echo "- Click the 'Run Workflow' button on the right-hand-side of the page"
    echo "- Under 'Use workflow' click 'from Branch: main'"
    echo "- Under 'select branch' paste: ${new_tag_name} and click 'Run'"
    echo "- Diff: https://github.com/letsencrypt/boulder/compare/${latest_tag_name}...${new_tag_name}"
    echo "- Once the CI pass has succeeded, run: git push origin --tags"
else
  exit_msg "No hotfix release branch was created, exiting..."
fi



# Because set -e stops execution in the instance of a command or pipeline error;
# if we got here we assume success
STATUS="SUCCESS"
