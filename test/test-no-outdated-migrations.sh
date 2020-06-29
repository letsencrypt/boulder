#!/bin/bash
cd $(dirname $0)/..
if [ ! -d .git ]; then
  echo "Not in a git repository, skipping out-of-order migration test."
fi

source test/db-common.sh

NEW_FILES_LIST=$(mktemp /tmp/new-files.XXXXX)
trap 'rm ${NEW_FILES_LIST}' EXIT

for svc in $SERVICES; do
  for dbenv in $DBENVS; do
    DB_DIR=$svc/_db/
    git diff --name-only main -- ${DB_DIR} > ${NEW_FILES_LIST}
    # Search for files in the migrations directory match the new files or come
    # lexically after them, then filter out the new files.
    GREP_OUT="$(ls ${DB_DIR}migrations/* | sort | \
      grep -A 1 -xf ${NEW_FILES_LIST} | \
      grep -vxf ${NEW_FILES_LIST})"
    if [ -n "${GREP_OUT}" ] ; then
      echo "--- New migrations on this branch: ---"
      cat $NEW_FILES_LIST
      echo "--- Existing migrations on master: ---"
      echo "${GREP_OUT}"
      echo
      echo "All migrations on a branch must be timestamped newer than"
      echo "migrations on master before they can be merged. Please"
      echo "rename migrations as appropriate."
      exit 1
    fi
  done
done
