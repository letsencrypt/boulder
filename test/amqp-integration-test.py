#!/usr/bin/env python2.7
import atexit
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile

import startservers


class ExitStatus:
    OK, PythonFailure, NodeFailure, Error, OCSPFailure = range(5)


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

def get_ocsp(certFile):
    openssl_ocsp_cmd = ("""
      openssl x509 -in %s -out %s.pem -inform der -outform pem;
      openssl ocsp -no_nonce -issuer ../test-ca.pem -CAfile ../test-ca.pem -cert %s.pem -url http://localhost:4002
    """ % (certFile, certFile, certFile))
    try:
        print openssl_ocsp_cmd
        output = subprocess.check_output(openssl_ocsp_cmd, shell=True)
    except subprocess.CalledProcessError as e:
        output = e.output
        print output
        print "OpenSSL returned non-zero: %s" % e
        die(ExitStatus.OCSPFailure)
    print output
    return output

def verify_ocsp_good(certFile):
    output = get_ocsp(certFile)
    if not re.search(": good", output):
        die(ExitStatus.OCSPFailure)

def verify_ocsp_revoked(certFile):
    output = get_ocsp(certFile)
    if not re.search(": revoked", output):
        die(ExitStatus.OCSPFailure)
    pass

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
    certFile = os.path.join(tempdir, "cert.der")
    keyFile = os.path.join(tempdir, "key.pem")
    if subprocess.Popen('''
        node test.js --email foo@letsencrypt.org --agree true \
          --domains foo.com --new-reg http://localhost:4000/acme/new-reg \
          --certKey %s --cert %s
        ''' % (keyFile, certFile), shell=True).wait() != 0:
        print("\nIssuing failed")
        die(ExitStatus.NodeFailure)

    verify_ocsp_good(certFile)

    if subprocess.Popen('''
        node revoke.js %s %s http://localhost:4000/acme/revoke-cert
        ''' % (certFile, keyFile), shell=True).wait() != 0:
        print("\nRevoking failed")
        die(ExitStatus.NodeFailure)

    verify_ocsp_revoked(certFile)

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
        print("\n\nFAILURE %d" % exit_status)


exit_status = ExitStatus.OK
tempdir = tempfile.mkdtemp()
if not startservers.start(race_detection=True):
    die(ExitStatus.Error)
run_node_test()
run_client_tests()
if not startservers.check():
    die(ExitStatus.Error)
