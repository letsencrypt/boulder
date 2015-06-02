#!/usr/bin/env python2.7
"""
Run a local instance of Boulder for testing purposes.

This runs in non-monolithic mode and requires RabbitMQ on localhost.
"""
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time

tempdir = tempfile.mkdtemp()

def run(path):
    binary = os.path.join(tempdir, os.path.basename(path))
    cmd = 'go build -o %s %s' % (binary, path)
    print(cmd)
    if subprocess.Popen(cmd, shell=True).wait() != 0:
        sys.exit(1)
    return subprocess.Popen('''
        exec %s --config test/boulder-config.json
        ''' % binary, shell=True)

processes = []

def start():
    # A strange Go bug: If cfssl is up-to-date, we'll get a failure building
    # Boulder. Work around by touching cfssl.go.
    subprocess.Popen('touch Godeps/_workspace/src/github.com/cloudflare/cfssl/cmd/cfssl/cfssl.go', shell=True).wait()
    global processes
    processes = [
        run('./cmd/boulder-wfe'),
        run('./cmd/boulder-ra'),
        run('./cmd/boulder-sa'),
        run('./cmd/boulder-ca'),
        run('./cmd/boulder-va'),
        subprocess.Popen('''
        exec %s/cfssl \
          -loglevel 0 \
          serve \
          -port 9300 \
          -ca test/test-ca.pem \
          -ca-key test/test-ca.key \
          -config test/cfssl-config.json
        ''' % tempdir, shell=True, stdout=None)]
    time.sleep(100000)

try:
    start()
finally:
    for p in processes:
        if p.poll() is None:
            p.kill()
