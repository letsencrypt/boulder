#!/bin/bash

set -e -u

socket="${1}"
max_tries=40

for n in $(seq 1 "${max_tries}"); do
  if [ -S "${socket}" ]; then
    echo "Socket ${socket} is ready"
    exit 0
  fi
  echo "$(date) - still waiting for socket ${socket}"
  sleep 1
done

echo "timed out waiting for socket ${socket}"
exit 1
