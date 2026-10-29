#!/bin/bash
# Note: only works for mariadb, not vitess.
set -feuxo pipefail
mysql -h boulder-mariadb -u root -D mtcmeta_44947_4_1_0_3 \
  -e "TRUNCATE TABLE checkpoints; TRUNCATE TABLE latestCheckpoint; TRUNCATE TABLE landmarks"

