#!/bin/bash

set -e -u

socket="${1}"
max_tries=40

for n in $(seq 1 "${max_tries}"); do
  if curl --silent --output /dev/null --unix-socket "${socket}" http://pkimetal/; then
    echo "Socket ${socket} is ready and serving HTTP"
    exit 0
  fi
  echo "$(date) - still waiting for socket ${socket}"
  sleep 1
done

echo "timed out waiting for socket ${socket}"
exit 1
