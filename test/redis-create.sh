redis-cli --cluster create \
  10.33.33.2:4218 10.33.33.3:4218 10.33.33.4:4218 \
  10.33.33.5:4218 10.33.33.6:4218 10.33.33.7:4218 \
  --cluster-replicas 1 \
  --tls \
  --cert /test/redis-tls/redis/cert.pem \
  --key /test/redis-tls/redis/key.pem \
  --cacert /test/redis-tls/minica.pem \
  --user ocsp-updater \
  --pass e4e9ce7845cb6adbbc44fb1d9deb05e6b4dc1386
