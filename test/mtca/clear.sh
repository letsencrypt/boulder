#!/bin/bash
set -feuxo pipefail
#mysql -h boulder-mariadb -u root -D mtcmeta_44947_4_1_0_44 -e "SELECT * from latestCheckpoint"
#mysql -h boulder-mariadb -u root -D mtcmeta_44947_4_1_0_44 -e "SELECT * from checkpoints"
mysql -h boulder-mariadb -u root -D mtcmeta_44947_4_1_0_44 -e "TRUNCATE TABLE checkpoints"
mysql -h boulder-mariadb -u root -D mtcmeta_44947_4_1_0_44 -e "TRUNCATE TABLE latestCheckpoint"
