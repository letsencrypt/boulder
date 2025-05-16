#!/usr/bin/env bash

function usage() {
  echo "./newLint.sh [-h|--help] -r|--req <REQUIREMENT> -n|--name <LINTNAME> -s|--struct <STRUCTNAME>"
  echo ""
  echo "Options:"
  echo "  -h|--help   Prints this help text."
  echo "  -r|--req    The name of the requirements body governing this lint. Valid options are $(valid_requirement_names)."
  echo "  -n|--name   The lintname for the given lints."
  echo "  -s|--struct The name of the Golang struct to create."
  echo ""
  echo "Example:"
  echo "  $ ./newLint.sh --req rfc --file crl_must_be_good --struct CrlMustBeGood "
  echo "    Created lint file /home/chris/projects/zlint/v3/lints/rfc/lint_crl_must_be_good.go with struct name CrlMustBeGood"
  echo "    Created test file /home/chris/projects/zlint/v3/lints/rfc/lint_crl_must_be_good_test.go"
}

function git_root() {
    git rev-parse --show-toplevel
}

# Searches within the v3/lints directory for a subdirectory matching
# the name of the governing requirements body provided by the -r|--req flag.
#
# Exits with error code 1 if no such directory is found
function requirement_dir_exists() {
    exists=$(find "$(git_root)/v3/lints/" -maxdepth 1 -type d -not -name lints -name "${1}")
    if [ -z "${exists}" ]; then
      echo "Unknown requirements body (${1}). Valid options are $(valid_requirement_names)."
      usage
      exit 1
    fi
}

# Echoes out a comma separated list of directories within v3/lints
function valid_requirement_names() {
    names=$(find "$(git_root)/v3/lints/" -type d -not -name "lints" -exec basename {} \;)
    echo -n "${names}" | tr '\n' ', '
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -r | --req)
      requirement_dir_exists "${2}"
      REQUIREMENT="${2}"
      shift 2
      ;;
    -n| --name)
      LINTNAME="${2}"
      shift 2
      ;;
    -s | --struct)
      STRUCTNAME="$2"
      shift 2
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      usage
      exit 1
      ;;
  esac
done

if [[ $LINTNAME =~ ^[enw]_ ]]; then
  FILENAME="lint_${LINTNAME:2}.go"
  TEST_FILENAME="lint_${LINTNAME:2}_test.go"
else
  echo "The lintname should start with e_, w_, n_"
  usage
  exit 1
fi

if [ -z "${REQUIREMENT}" ]; then
  echo "The -r|--req flag is required. Valid options are $(valid_requirement_names)"
  usage
  exit 1
fi

if [ -z "${LINTNAME}" ]; then
  echo "The -n|--name flag is required."
  usage
  exit 1
fi

if [ -z "${STRUCTNAME}" ]; then
  echo "The -s|--struct flag is required."
  usage
  exit 1
fi

PATHNAME="$(git_root)/v3/lints/${REQUIREMENT}/${FILENAME}"
TEST_PATHNAME="$(git_root)/v3/lints/${REQUIREMENT}/${TEST_FILENAME}"

sed -e "s/PACKAGE/${REQUIREMENT}/" \
    -e "s/PASCAL_CASE_SUBST/${STRUCTNAME}/g" \
    -e "s/SUBST/${STRUCTNAME}/g" \
    -e "s/SUBTEST/${LINTNAME}/g" "$(git_root)/v3/template" > "${PATHNAME}"

sed -e "s/PACKAGE/${REQUIREMENT}/" \
    -e "s/PASCAL_CASE_SUBST/${STRUCTNAME}/g" \
    -e "s/SUBST/${STRUCTNAME}/g" \
    -e "s/SUBTEST/${LINTNAME}/g" "$(git_root)/v3/test_template" > "${TEST_PATHNAME}"

echo "Created lint file ${PATHNAME} with struct name ${STRUCTNAME}"
echo "Created test file ${TEST_PATHNAME}"
