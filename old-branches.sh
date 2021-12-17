#!/usr/bin/bash

out=''
while read -r line; do
  elems=($line)
  out+=$(printf "%s:%s" $(git show -s --format="%cs" ${elems[0]}) ${elems[1]})
  out+="\n"
done <<< $(git ls-remote -h origin)

printf "${out}" | column -t -s ":" | sort
