#!/bin/bash

default_unix_socket='/dev/log'
custom_file_path='/syslog/log'

# Wait for the logger sidecar to initialize
until ls ${custom_file_path} > /dev/null 2>&1; do
  echo "Logger sidecar container is not ready yet"
  sleep 1
done

echo "Logger sidecar container is ready"

# Kubernetes will mount the volume containing the
# rsyslogd unix socket provided by the sidecar
# to ${custom_file_path}
ln -s ${custom_file_path} ${default_unix_socket}

exec $@
