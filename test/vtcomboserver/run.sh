#!/bin/bash

# Much of the below is adapted from upstream Vitess's vttestserver run.sh
# but instead of using vttestserver, we use vtcombo directly:
# https://github.com/vitessio/vitess/blob/v22.0.1/docker/vttestserver/run.sh

# Copyright 2021 The Vitess Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Set the maximum connections in the cnf file
# use 1000 as the default if it is unspecified
if [[ -z $MYSQL_MAX_CONNECTIONS ]]; then
  MYSQL_MAX_CONNECTIONS=1000
fi
echo "max_connections = $MYSQL_MAX_CONNECTIONS" >> /vt/config/mycnf/test-suite.cnf

# Delete socket files before running mysqlctld if exists.
# This is the primary reason for unhealthy state on restart.
# https://github.com/vitessio/vitess/pull/5115/files
rm -vf "$VTDATAROOT"/"$tablet_dir"/{mysql.sock,mysql.sock.lock}

# Kick off script to install trigger we use to simulate
# errors in our integration tests, in the background.
/vt/install_trigger.sh &

/vt/bin/vttestserver \
  --alsologtostderr \
  --data-dir=/vt/vtdataroot/ \
  --schema-dir=/vt/schema/ \
  --persistent_mode \
  --port=33574 \
  --mysql-bind-host=0.0.0.0 \
  --vtcombo-bind-host=0.0.0.0 \
  --keyspaces="${KEYSPACES}" \
  --num-shards="${NUM_SHARDS}"
