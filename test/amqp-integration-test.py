#!/usr/bin/env python2.7
import atexit
import base64
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import urllib
import time
import urllib2

import startservers


class ExitStatus:
    OK, PythonFailure, NodeFailure, Error, OCSPFailure, CTFailure = range(6)


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

# Fetch an OCSP response, parse it with OpenSSL, and return the output.
def get_ocsp(cert_file, url):
    ocsp_req_file = os.path.join(tempdir, "ocsp.req")
    ocsp_resp_file = os.path.join(tempdir, "ocsp.resp")
    # First generate the OCSP request in DER form
    openssl_ocsp = "openssl ocsp -issuer ../test-ca.pem -cert %s.pem" % cert_file
    openssl_ocsp_cmd = ("""
      openssl x509 -in %s -out %s.pem -inform der -outform pem;
      %s -no_nonce -reqout %s
    """ % (cert_file, cert_file, openssl_ocsp, ocsp_req_file))
    print openssl_ocsp_cmd
    subprocess.check_output(openssl_ocsp_cmd, shell=True)
    with open(ocsp_req_file) as f:
        ocsp_req = f.read()
    ocsp_req_b64 = base64.b64encode(ocsp_req)

    # Make the OCSP request three different ways: by POST, by GET, and by GET with
    # URL-encoded parameters. All three should have an identical response.
    get_response = urllib2.urlopen("%s/%s" % (url, ocsp_req_b64)).read()
    get_encoded_response = urllib2.urlopen("%s/%s" % (url, urllib.quote(ocsp_req_b64, safe = ""))).read()
    post_response = urllib2.urlopen("%s/" % (url), ocsp_req).read()

    if get_response != get_encoded_response:
        print "OCSP responses for GET and URL-encoded GET differed."
        die(ExitStatus.OCSPFailure)
    elif get_response != post_response:
        print "OCSP responses for GET and POST differed."
        die(ExitStatus.OCSPFailure)

    with open(ocsp_resp_file, "w") as f:
        f.write(get_response)

    ocsp_verify_cmd = "%s -CAfile ../test-ca.pem -respin %s" % (openssl_ocsp, ocsp_resp_file)
    print ocsp_verify_cmd
    try:
        output = subprocess.check_output(ocsp_verify_cmd, shell=True)
    except subprocess.CalledProcessError as e:
        output = e.output
        print output
        print "subprocess returned non-zero: %s" % e
        die(ExitStatus.OCSPFailure)

    print output
    return output

def verify_ocsp_good(certFile, url):
    output = get_ocsp(certFile, url)
    if not re.search(": good", output):
        if not re.search(" unauthorized \(6\)", output):
            print "Expected OCSP response 'unauthorized', got something else."
            die(ExitStatus.OCSPFailure)
        return False
    return True

def verify_ocsp_revoked(certFile, url):
    output = get_ocsp(certFile, url)
    if not re.search(": revoked", output):
        print "Expected OCSP response 'revoked', got something else."
        die(ExitStatus.OCSPFailure)
    pass

# loop_check expects the function passed as action will return True/False to indicate
# success/failure
def loop_check(failureStatus, action, *args):
    timeout = time.time() + 5
    while True:
        if action(*args):
            break
        if time.time() > timeout:
            die(failureStatus)
        time.sleep(0.25)

def verify_ct_submission(expectedSubmissions, url):
    resp = urllib2.urlopen(url)
    submissionStr = resp.read()
    if int(submissionStr) != expectedSubmissions:
        print "Expected %d submissions, found %d" % (expectedSubmissions, int(submissionStr))
        die(ExitStatus.CTFailure)

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
    # Pick a random hostname so we don't run into certificate rate limiting.
    domain = subprocess.check_output("openssl rand -hex 6", shell=True).strip()
    if subprocess.Popen('''
        node test.js --email foo@letsencrypt.org --agree true \
          --domains www.%s.com --new-reg http://localhost:4000/acme/new-reg \
          --certKey %s --cert %s
        ''' % (domain, keyFile, certFile), shell=True).wait() != 0:
        print("\nIssuing failed")
        die(ExitStatus.NodeFailure)

    ee_ocsp_url = "http://localhost:4002"
    issuer_ocsp_url = "http://localhost:4003"

    # Also verify that the static OCSP responder, which answers with a
    # pre-signed, long-lived response for the CA cert, also works.
    verify_ocsp_good("../test-ca.der", issuer_ocsp_url)

    # As OCSP-Updater is generating responses indepedantly of the CA we sit in a loop
    # checking OCSP until we either see a good response or we timeout (5s).
    loop_check(ExitStatus.OCSPFailure, verify_ocsp_good, certFile, ee_ocsp_url)

    verify_ct_submission(1, "http://localhost:4500/submissions")

    if subprocess.Popen('''
        node revoke.js %s %s http://localhost:4000/acme/revoke-cert
        ''' % (certFile, keyFile), shell=True).wait() != 0:
        print("\nRevoking failed")
        die(ExitStatus.NodeFailure)

    verify_ocsp_revoked(certFile, ee_ocsp_url)

    return 0


def run_client_tests():
    root = os.environ.get("LETSENCRYPT_PATH")
    assert root is not None, (
        "Please set LETSENCRYPT_PATH env variable to point at "
        "initialized (virtualenv) client repo root")
    test_script_path = os.path.join(root, 'tests', 'boulder-integration.sh')
    cmd = "source %s/venv/bin/activate && %s" % (root, test_script_path)
    if subprocess.Popen(cmd, shell=True, cwd=root, executable='/bin/bash').wait() != 0:
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
