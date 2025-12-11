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

# Setup the Vschema Folder
/vt/setup_vschema_folder.sh "$KEYSPACES" "$NUM_SHARDS"

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

# Create Vitess JSON topo, start vtcombo and mysql. For more details see:
#   - https://vitess.io/docs/22.0/reference/programs/vtcombo
#   - https://github.com/vitessio/vitess/blob/v22.0.1/go/vt/vttest/vtprocess.go
#   - https://github.com/vitessio/vitess/blob/v22.0.1/proto/vttest.proto
/vt/bin/vtcombo \
  --port "${PORT:-33574}" \
  --bind-address "${VTCOMBO_BIND_HOST:-0.0.0.0}" \
  --mysql_server_bind_address "${MYSQL_SERVER_BIND_ADDRESS:-0.0.0.0}" \
  --mysql_server_port "${MYSQL_SERVER_PORT:-33577}" \
  --mysql_auth_server_impl "none" \
  --mysql_server_version "${MYSQL_SERVER_VERSION:-8.0.40-Vitess}" \
  --db_charset "${CHARSET:-utf8mb4}" \
  --foreign_key_mode "${FOREIGN_KEY_MODE:-allow}" \
  --enable_online_ddl \
  --enable_direct_ddl \
  --planner-version "${PLANNER_VERSION:-gen4}" \
  --vschema_ddl_authorized_users "${VSCHEMA_DDL_AUTH_USERS:-%}" \
  --tablet_refresh_interval "${TABLET_REFRESH_INTERVAL:-10s}" \
  --schema_dir "/vt/schema" \
  --queryserver-config-max-result-size "${QUERY_MAX_RESULT_SIZE:-1000000}" \
  --queryserver-config-warn-result-size "${QUERY_WARN_RESULT_SIZE:-1000000}" \
  --normalize_queries \
  --queryserver-config-pool-size 64 \
  --queryserver-config-stream-pool-size 200 \
  --queryserver-config-transaction-cap 80 \
  --queryserver-config-query-timeout 300s \
  --queryserver-config-schema-reload-time 60s \
  --queryserver-config-txpool-timeout 300s \
  --json_topo "$(printf '{"cells":["test"],"keyspaces":[%s]}' \
    "$(IFS=, read -ra ks <<< "${KEYSPACES}"; \
       for i in "${!ks[@]}"; do \
         printf '%s{"name":"%s","shards":[{"name":"0"}]}' \
           "$([ $i -gt 0 ] && echo ,)" "${ks[$i]}"; \
       done)")" \
  --start_mysql
