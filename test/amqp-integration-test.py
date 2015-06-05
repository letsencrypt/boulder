#!/usr/bin/env python2.7
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time

tempdir = tempfile.mkdtemp()

exit_status = 0

def die():
    global exit_status
    exit_status = 1
    sys.exit(1)

processes = []

def run(path):
    global processes
    binary = os.path.join(tempdir, os.path.basename(path))
    cmd = 'go build -tags pkcs11 -o %s %s' % (binary, path)
    print(cmd)
    if subprocess.Popen(cmd, shell=True).wait() != 0:
        die()
    processes.append(subprocess.Popen('''
        exec %s --config test/boulder-test-config.json
        ''' % binary, shell=True))

def start():
    run('./cmd/boulder-wfe')
    run('./cmd/boulder-ra')
    run('./cmd/boulder-sa')
    run('./cmd/boulder-ca')
    run('./cmd/boulder-va')

def run_test():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect(('localhost', 4300))
    except socket.error, e:
        print("Cannot connect to WFE")
        die()

    os.chdir('test/js')

    if subprocess.Popen('npm install', shell=True).wait() != 0:
        print("\n Installing NPM modules failed")
        die()
    if subprocess.Popen('''
        node test.js --email foo@bar.com --agree true \
          --domains foo.com --new-reg http://localhost:4300/acme/new-reg \
          --certKey %s/key.pem --cert %s/cert.der
        ''' % (tempdir, tempdir), shell=True).wait() != 0:
        print("\nIssuing failed")
        die()
    if subprocess.Popen('''
        node revoke.js %s/cert.der %s/key.pem http://localhost:4300/acme/revoke-cert/
        ''' % (tempdir, tempdir), shell=True).wait() != 0:
        print("\nRevoking failed")
        die()

    return 0

try:
    start()
    run_test()
except Exception as e:
    exit_status = 1
    print e
finally:
    for p in processes:
        if p.poll() is None:
            p.kill()
        else:
            exit_status = 1

    shutil.rmtree(tempdir)

    if exit_status == 0:
        print("\n\nSUCCESS")
    else:
        print("\n\nFAILURE")
    sys.exit(exit_status)
