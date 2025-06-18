#!/usr/bin/env bash
#
# Usage: verify-release-ancestry.sh <commit hash>
#
# Exits zero if the provided commit is either an ancestor of main or equal to a
# hotfix branch (release-branch-*). Exits 1 otherwise.
#
set -u

if git merge-base --is-ancestor "$1" origin/main || git name-rev --no-undefined --refs 'refs/remotes/origin/release-branch-*' "$1" ; then
  exit 0
else
  echo
  echo "Commit '$1' was neither an ancestor of main nor equal to a hotfix branch (release-branch-*)"
  echo
  exit 1
fi
