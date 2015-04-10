#!/bin/bash
cfssl -loglevel 0 serve -port 9000 \
  -ca test/test-ca.pem \
  -ca-key test/test-ca.key \
  -config test/cfssl-config.json
