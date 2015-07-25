#!/usr/bin/env python2.7
import atexit
import os
import shutil
import socket
import subprocess
import sys
import tempfile

import startservers


class ExitStatus:
    OK, PythonFailure, NodeFailure, Error = range(4)


class ProcInfo:
    """
        Args:
            cmd (str): The command that was run
            proc(subprocess.Popen): The Popen of the command run
    """

    def __init__(self, cmd, proc):
        self.cmd = cmd
        self.proc = proc


def die(status):
    global exit_status
    # Set exit_status so cleanup handler knows what to report.
    exit_status = status
    sys.exit(exit_status)


def run_node_test():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect(('localhost', 4000))
    except socket.error, e:
        print("Cannot connect to WFE")
        die(ExitStatus.Error)

    os.chdir('test/js')

    if subprocess.Popen('npm install', shell=True).wait() != 0:
        print("\n Installing NPM modules failed")
        die(ExitStatus.Error)
    if subprocess.Popen('''
        node test.js --email foo@letsencrypt.org --agree true \
          --domains foo.com --new-reg http://localhost:4000/acme/new-reg \
          --certKey %s/key.pem --cert %s/cert.der
        ''' % (tempdir, tempdir), shell=True).wait() != 0:
        print("\nIssuing failed")
        die(ExitStatus.NodeFailure)
    if subprocess.Popen('''
        node revoke.js %s/cert.der %s/key.pem http://localhost:4000/acme/revoke-cert
        ''' % (tempdir, tempdir), shell=True).wait() != 0:
        print("\nRevoking failed")
        die(ExitStatus.NodeFailure)

    return 0


def run_client_tests():
    root = os.environ.get("LETSENCRYPT_PATH")
    assert root is not None, (
        "Please set LETSENCRYPT_PATH env variable to point at "
        "initialized (virtualenv) client repo root")
    os.environ['SERVER'] = 'http://localhost:4000/acme/new-reg'
    test_script_path = os.path.join(root, 'tests', 'boulder-integration.sh')
    if subprocess.Popen(test_script_path, shell=True, cwd=root).wait() != 0:
        die(ExitStatus.PythonFailure)


@atexit.register
def cleanup():
    import shutil
    shutil.rmtree(tempdir)
    if exit_status == ExitStatus.OK:
        print("\n\nSUCCESS")
    else:
        print("\n\nFAILURE")


exit_status = ExitStatus.OK
tempdir = tempfile.mkdtemp()
if not startservers.start():
    die(ExitStatus.Error)
run_node_test()
run_client_tests()
if not startservers.check():
    die(ExitStatus.Error)
