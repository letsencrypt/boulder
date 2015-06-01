#!/usr/bin/env python2.7
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
        exec %s --config test/boulder-test-config.json
        ''' % binary, shell=True)

processes = []

def start():
    # A strange Go bug: If cfssl is up-to-date, we'll get a failure building
    # Boulder. Work around by touching cfssl.go.
    subprocess.Popen('touch Godeps/_workspace/src/github.com/cloudflare/cfssl/cmd/cfssl/cfssl.go', shell=True).wait()
    cmd = 'go build -o %s/cfssl ./Godeps/_workspace/src/github.com/cloudflare/cfssl/cmd/cfssl' % (tempdir)
    print(cmd)
    if subprocess.Popen(cmd, shell=True).wait() != 0:
        sys.exit(1)
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
    # time.sleep(30)

def run_test():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect(('localhost', 4300))
    except socket.error, e:
        print("Cannot connect to WFE")
        sys.exit(1)

    os.chdir('test/js')

    issue = subprocess.Popen('''
        node test.js --email foo@bar.com --agree true \
          --domain foo.com --new-reg http://localhost:4300/acme/new-reg \
          --certKey %s/key.pem --cert %s/cert.der
        ''' % (tempdir, tempdir), shell=True)
    if issue.wait() != 0:
        print("\nIssuing failed")
        return 1
    revoke = subprocess.Popen('''
        node revoke.js %s/cert.der %s/key.pem http://localhost:4300/acme/revoke-cert/
        ''' % (tempdir, tempdir), shell=True)
    if revoke.wait() != 0:
        print("\nRevoking failed")
        return 1
    return 0

try:
    start()
    status = run_test()
finally:
    for p in processes:
        if p.poll() is None:
            p.kill()
        else:
            status = 1
    if status == 0:
        print("\n\nSUCCESS")
    else:
        print("\n\nFAILURE")
    sys.exit(status)