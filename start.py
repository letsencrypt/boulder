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

config = os.environ.get('BOULDER_CONFIG')
if config is None:
	config = 'test/boulder-config.json'

def run(path):
    binary = os.path.join(tempdir, os.path.basename(path))
    cmd = 'go build -o %s %s' % (binary, path)
    print(cmd)
    if subprocess.Popen(cmd, shell=True).wait() != 0:
        sys.exit(1)
    return subprocess.Popen('''
        exec %s --config %s
        ''' % (binary, config), shell=True)

processes = []

def start():
    global processes
    processes = [
        run('./cmd/boulder-wfe'),
        run('./cmd/boulder-ra'),
        run('./cmd/boulder-sa'),
        run('./cmd/boulder-ca'),
        run('./cmd/boulder-va')]
    time.sleep(100000)

try:
    start()
finally:
    for p in processes:
        if p.poll() is None:
            p.kill()
