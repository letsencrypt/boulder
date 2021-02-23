#!/usr/bin/env bash

set -eu
STATUS="ERROR"
PLUGINS_PATH="observer/plugins/"
esc=$'\033'
aesc="${esc}[" # posix compliant escape sequence


function print_outcome() {
  if [ "$STATUS" == OK ]
  then
    echo -e "${aesc}0;32m""$STATUS""${aesc}0m"
  else
    echo -e "${aesc}0;31m""$STATUS""${aesc}0m"
  fi
}
function print_heading() {
  echo -e "${aesc}0;34m"$1"${aesc}0m"
}

function print_entry() {
  echo -e "${aesc}0;36m"$1"${aesc}0m"
}

#
# Detect exit and print outcome
#
trap "print_outcome" EXIT

#
# Look for plugins to compile
#
plugins=( $(find $PLUGINS_PATH -mindepth 1 -maxdepth 1 -not -path '*/\.*' -type d  2> /dev/null | sort) )
if [ -z "${plugins[@]+x}" ]
then
  echo "There are no plugins at path: "\"$PLUGINS_PATH\"""
  exit 1
fi

#
# Clean and compile observer plugins
#
print_heading "Building plugins:"
for plugin in "${plugins[@]}"
do
  # for each <dirname>, attempt to build a <dirname>.so
  print_entry "⚙️ "${plugin}".so"
  if [ -f "${plugin}".so ]
  then
    # force remove because previously compiled .so files are protected
    rm -f "${plugin}".so
  fi
  $(go build -buildmode=plugin -o "${plugin}".so "${PLUGINS_PATH}"/$(basename -- "${plugin}")/*.go)
  print_entry "✅$(basename -- "${plugin}").so"
done

# assume success if we got here
STATUS="OK"
