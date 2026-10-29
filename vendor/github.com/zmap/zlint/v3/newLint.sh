#!/usr/bin/env bash
#
# Scaffolds a new certificate lint and its test file from `template` and
# `test_template`.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LINTS_DIR="${SCRIPT_DIR}/lints"

usage() {
  cat <<EOF
Usage: ./newLint.sh -r|--req <REQUIREMENT> -n|--name <LINTNAME> [-s|--struct <STRUCTNAME>]

Options:
  -h|--help    Prints this help text.
  -r|--req     The requirements body governing this lint, i.e. a directory
               under v3/lints. Valid options are: $(valid_requirement_names).
  -n|--name    The lint name. Must start with e_, w_ or n_ and contain only
               lowercase letters, digits and underscores.
  -s|--struct  The name of the Go struct to create. Optional; by default it is
               derived from the lint name (e_foo_bar becomes fooBar). Provide
               it when the name contains an acronym, e.g. subjectCommonNameNotFromSAN.

Example:
  \$ ./newLint.sh --req rfc --name e_crl_must_be_good --struct crlMustBeGood
    Created lint file ${LINTS_DIR}/rfc/lint_crl_must_be_good.go
    Created test file ${LINTS_DIR}/rfc/lint_crl_must_be_good_test.go
EOF
}

die() {
  echo "Error: $*" >&2
  echo >&2
  usage >&2
  exit 1
}

# Echoes a comma separated list of the directories within v3/lints.
valid_requirement_names() {
  find "${LINTS_DIR}" -mindepth 1 -maxdepth 1 -type d -exec basename {} \; | sort | paste -sd, - | sed 's/,/, /g'
}

# Derives a lowerCamelCase struct name from a lint name: e_foo_bar => fooBar.
derive_struct_name() {
  local -a words
  local result="" i
  IFS=_ read -ra words <<<"${1:2}"
  for i in "${!words[@]}"; do
    if [[ ${i} -eq 0 ]]; then
      result+="${words[i]}"
    else
      result+="${words[i]^}"
    fi
  done
  echo "${result}"
}

# render <template> <destination>
render() {
  sed -e "s/PACKAGE/${REQUIREMENT}/g" \
    -e "s/PASCAL_CASE_SUBST/${PASCAL_NAME}/g" \
    -e "s/SUBST/${STRUCTNAME}/g" \
    -e "s/SUBTEST/${LINTNAME}/g" "$1" >"$2"
}

REQUIREMENT=""
LINTNAME=""
STRUCTNAME=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h | --help)
      usage
      exit 0
      ;;
    -r | --req | -n | --name | -s | --struct)
      [[ $# -ge 2 ]] || die "$1 requires a value."
      case "$1" in
        -r | --req) REQUIREMENT="$2" ;;
        -n | --name) LINTNAME="$2" ;;
        -s | --struct) STRUCTNAME="$2" ;;
      esac
      shift 2
      ;;
    *)
      die "Unknown option: $1"
      ;;
  esac
done

[[ -n "${REQUIREMENT}" ]] || die "The -r|--req flag is required."
[[ -n "${LINTNAME}" ]] || die "The -n|--name flag is required."

[[ -d "${LINTS_DIR}/${REQUIREMENT}" ]] ||
  die "Unknown requirements body (${REQUIREMENT}). Valid options are $(valid_requirement_names)."

[[ "${LINTNAME}" =~ ^[enw]_[a-z0-9]+(_[a-z0-9]+)*$ ]] ||
  die "Invalid lint name (${LINTNAME}). It must start with e_, w_ or n_ and contain only lowercase letters, digits and underscores."

if [[ -z "${STRUCTNAME}" ]]; then
  STRUCTNAME="$(derive_struct_name "${LINTNAME}")"
fi
[[ "${STRUCTNAME}" =~ ^[A-Za-z][A-Za-z0-9]*$ ]] ||
  die "Invalid struct name (${STRUCTNAME}). It must be a Go identifier of letters and digits."

# The constructor and test function names must be exported, regardless of
# whether the struct itself is.
PASCAL_NAME="${STRUCTNAME^}"

BASENAME="lint_${LINTNAME:2}"
LINT_PATH="${LINTS_DIR}/${REQUIREMENT}/${BASENAME}.go"
TEST_PATH="${LINTS_DIR}/${REQUIREMENT}/${BASENAME}_test.go"

for path in "${LINT_PATH}" "${TEST_PATH}"; do
  [[ ! -e "${path}" ]] || die "${path} already exists."
done

# Lint names are global, and only the e_/w_/n_ prefix distinguishes severity
# in the file name, so check for the name itself being registered already.
if grep -rqF --include='*.go' "\"${LINTNAME}\"" "${LINTS_DIR}"; then
  die "A lint named ${LINTNAME} already exists."
fi
if grep -qE "^type ${STRUCTNAME} " "${LINTS_DIR}/${REQUIREMENT}"/*.go; then
  die "A type named ${STRUCTNAME} already exists in package ${REQUIREMENT}."
fi

render "${SCRIPT_DIR}/template" "${LINT_PATH}"
render "${SCRIPT_DIR}/test_template" "${TEST_PATH}"

echo "Created lint file ${LINT_PATH}"
echo "Created test file ${TEST_PATH}"
echo
echo "Next: fill in the lint metadata, CheckApplies and Execute, and replace"
echo "TEST_CERT.pem in the test with a certificate from testdata/."
