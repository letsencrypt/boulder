#!/usr/bin/bash

timerange=$1

out=''
branches=()
while read -r line; do
  elems=($line)
  name=${elems[1]#"refs/heads/"}
  if [[ ${name} == release* ]]; then
    continue
  fi
  hash=${elems[0]}
  date=$(git show -s --format="%cs" ${hash})
  if [[ ${date} != ${timerange}* ]]; then
    continue
  fi
  out+=$(printf "%s:%s" ${date} ${name})
  out+="\n"
  branches+=(${name})
done <<< $(git ls-remote -h origin)

echo "Going to delete the following branches:"
echo
printf "${out}" | column -t -s ":" | sort
echo
read -p "Type [yY] to continue: " -n 1 -r
echo

if [[ ! ${REPLY} =~ ^[yY]$ ]]; then
  echo "Aborting"
  exit
fi

#TODO: Replace -n (dry-run) with -f (force) for this to actually work.
for branch in ${branches[@]}; do
  git push origin -n -d ${branch}
done
