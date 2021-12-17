#!/usr/bin/bash

out=''
while read -r line; do
  elems=($line)
  name=${elems[1]#"refs/heads/"}
  hash=${elems[0]}
  date=$(git show -s --format="%cs" ${hash})
  out+=$(printf "%s:%s" ${date} ${name})
  out+="\n"
done <<< $(git ls-remote -h origin)

printf "${out}" | column -t -s ":" | sort
