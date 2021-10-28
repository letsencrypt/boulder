#!/bin/bash

redis-cli \
  --cluster-yes \
  --cluster create \
    10.33.33.2:4218 10.33.33.3:4218 10.33.33.4:4218 \
    10.33.33.5:4218 10.33.33.6:4218 10.33.33.7:4218 \
  --cluster-replicas 1 \
  --tls \
  --cert /test/redis-tls/redis/cert.pem \
  --key /test/redis-tls/redis/key.pem \
  --cacert /test/redis-tls/minica.pem \
  --user replication-user \
  --pass 435e9c4225f08813ef3af7c725f0d30d263b9cd3
