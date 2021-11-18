#!/usr/bin/env bash
#
# Symlink the various boulder subcommands into place.
#
BIN="${1}"
BINDIR="$(dirname $BIN)"
echo $BINDIR
mkdir -p $BINDIR/symlinks
for n in `"${BIN}" --list` ; do
  ln -sf boulder "$BINDIR"/symlinks/"$n"
done
