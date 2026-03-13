This directory contains the [vschema] files for each of our keyspaces.
At runtime (of the bvitess container), it will be combined into a new
directory with the .sql files from sa/db/, and passed to vttestserver
with the `--schema-dir` flag. The combined directory only exists inside
the bvitess container.

The setup is done by test/vttestserver/run.sh.

[vschema]: https://vitess.io/docs/23.0/reference/features/vschema/
