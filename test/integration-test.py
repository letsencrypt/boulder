#!/usr/bin/env python2.7
import argparse
import atexit
import base64
import datetime
import errno
import json
import os
import random
import re
import shutil
import subprocess
import signal
import sys
import tempfile
import time
import urllib2

import startservers

import chisel
from chisel import auth_and_issue

class ExitStatus:
    OK, PythonFailure, NodeFailure, Error, OCSPFailure, CTFailure, IncorrectCommandLineArgs, RevokerFailure, GSBFailure = range(9)

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

def fetch_ocsp(request_bytes, url):
    """Fetch an OCSP response using POST, GET, and GET with URL encoding.

    Returns a tuple of the responses.
    """
    ocsp_req_b64 = base64.b64encode(request_bytes)

    # Make the OCSP request three different ways: by POST, by GET, and by GET with
    # URL-encoded parameters. All three should have an identical response.
    get_response = urllib2.urlopen("%s/%s" % (url, ocsp_req_b64)).read()
    get_encoded_response = urllib2.urlopen("%s/%s" % (url, urllib2.quote(ocsp_req_b64, safe = ""))).read()
    post_response = urllib2.urlopen("%s/" % (url), request_bytes).read()

    return (post_response, get_response, get_encoded_response)

def make_ocsp_req(cert_file, issuer_file):
    """Return the bytes of an OCSP request for the given certificate file."""
    ocsp_req_file = os.path.join(tempdir, "ocsp.req")
    # First generate the OCSP request in DER form
    cmd = ("openssl ocsp -no_nonce -issuer %s -cert %s -reqout %s" % (
        issuer_file, cert_file, ocsp_req_file))
    print cmd
    subprocess.check_output(cmd, shell=True)
    with open(ocsp_req_file) as f:
        ocsp_req = f.read()
    return ocsp_req

def fetch_until(cert_file, issuer_file, url, initial, final):
    """Fetch OCSP for cert_file until OCSP status goes from initial to final.

    Initial and final are treated as regular expressions. Any OCSP response
    whose OpenSSL OCSP verify output doesn't match either initial or final is
    a fatal error.

    If OCSP responses by the three methods (POST, GET, URL-encoded GET) differ
    from each other, that is a fatal error.

    If we loop for more than five seconds, that is a fatal error.

    Returns nothing on success.
    """
    ocsp_request = make_ocsp_req(cert_file, issuer_file)
    timeout = time.time() + 5
    while True:
        time.sleep(0.25)
        if time.time() > timeout:
            print("Timed out waiting for OCSP to go from '%s' to '%s'" % (
                initial, final))
            die(ExitStatus.OCSPFailure)
        responses = fetch_ocsp(ocsp_request, url)
        # This variable will be true at the end of the loop if all the responses
        # matched the final state.
        all_final = True
        for resp in responses:
            verify_output = ocsp_verify(cert_file, issuer_file, resp)
            if re.search(initial, verify_output):
                all_final = False
                break
            elif re.search(final, verify_output):
                continue
            else:
                print verify_output
                print("OCSP response didn't match '%s' or '%s'" %(
                    initial, final))
                die(ExitStatus.OCSPFailure)
        if all_final:
            # Check that all responses were equal to each other.
            for resp in responses:
                if resp != responses[0]:
                    print "OCSP responses differed:"
                    print(base64.b64encode(responses[0]))
                    print(" vs ")
                    print(base64.b64encode(resp))
                    die(ExitStatus.OCSPFailure)
            return

def ocsp_verify(cert_file, issuer_file, ocsp_response):
    ocsp_resp_file = os.path.join(tempdir, "ocsp.resp")
    with open(ocsp_resp_file, "w") as f:
        f.write(ocsp_response)
    ocsp_verify_cmd = """openssl ocsp -no_nonce -issuer %s -cert %s \
      -verify_other %s -CAfile test/test-root.pem \
      -respin %s""" % (issuer_file, cert_file, issuer_file, ocsp_resp_file)
    print ocsp_verify_cmd
    try:
        output = subprocess.check_output(ocsp_verify_cmd,
            shell=True, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        output = e.output
        print output
        print "subprocess returned non-zero: %s" % e
        die(ExitStatus.OCSPFailure)
    # OpenSSL doesn't always return non-zero when response verify fails, so we
    # also look for the string "Response Verify Failure"
    verify_failure = "Response Verify Failure"
    if re.search(verify_failure, output):
        print output
        die(ExitStatus.OCSPFailure)
    return output

def wait_for_ocsp_good(cert_file, issuer_file, url):
    fetch_until(cert_file, issuer_file, url, " unauthorized", ": good")

def wait_for_ocsp_revoked(cert_file, issuer_file, url):
    fetch_until(cert_file, issuer_file, url, ": good", ": revoked")

def test_multidomain():
    auth_and_issue([random_domain(), random_domain()])

def test_gsb_lookups():
    """Attempt issuances for a GSB-blocked domain, and expect it to fail. Also
       check the gsb-test-srv's count of received queries to ensure it got a
       request."""
    # TODO(jsha): Once gsbv4 is enabled in both config and config-next, remove
    # this early return.
    if not default_config_dir.startswith("test/config-next"):
        return

    hostname = "honest.achmeds.discount.hosting.com"
    chisel.expect_problem("urn:acme:error:unauthorized",
        lambda: auth_and_issue([hostname]))

    hits_map = json.loads(urllib2.urlopen("http://localhost:6000/hits").read())

    # The GSB test server tracks hits with a trailing / on the URL
    hits = hits_map.get(hostname + "/", 0)
    if hits != 1:
        raise("Expected %d Google Safe Browsing lookups for %s, found %d" % (1, url, actual))

def test_ocsp():
    cert_file_pem = os.path.join(tempdir, "cert.pem")
    auth_and_issue([random_domain()], cert_output=cert_file_pem)

    ee_ocsp_url = "http://localhost:4002"

    # As OCSP-Updater is generating responses independently of the CA we sit in a loop
    # checking OCSP until we either see a good response or we timeout (5s).
    wait_for_ocsp_good(cert_file_pem, "test/test-ca2.pem", ee_ocsp_url)

def test_ct_submission():
    url = "http://localhost:4500/submissions"
    submissions = urllib2.urlopen(url).read()
    expected_submissions = int(submissions)+1
    auth_and_issue([random_domain()])
    submissions = urllib2.urlopen(url).read()
    if int(submissions) != expected_submissions:
        print "Expected %d submissions, found %s" % (expected_submissions, submissions)
        die(ExitStatus.CTFailure)

def random_domain():
    """Generate a random domain for testing (to avoid rate limiting)."""
    return "rand.%x.xyz" % random.randrange(2**32)

def test_expiration_mailer():
    email_addr = "integration.%x@boulder.local" % random.randrange(2**16)
    cert = auth_and_issue([random_domain()], email=email_addr).body
    # Check that the expiration mailer sends a reminder
    expiry = datetime.datetime.strptime(cert.get_notAfter(), '%Y%m%d%H%M%SZ')
    no_reminder = expiry + datetime.timedelta(days=-31)
    first_reminder = expiry + datetime.timedelta(days=-13)
    last_reminder = expiry + datetime.timedelta(days=-2)
    try:
        urllib2.urlopen("http://localhost:9381/clear", data='')
        print get_future_output('./bin/expiration-mailer --config %s/expiration-mailer.json' %
            default_config_dir, no_reminder)
        print get_future_output('./bin/expiration-mailer --config %s/expiration-mailer.json' %
            default_config_dir, first_reminder)
        print get_future_output('./bin/expiration-mailer --config %s/expiration-mailer.json' %
            default_config_dir, last_reminder)
        resp = urllib2.urlopen("http://localhost:9381/count?to=%s" % email_addr)
        mailcount = int(resp.read())
        if mailcount != 2:
            print("\nExpiry mailer failed: expected 2 emails, got %d" % mailcount)
            die(1)
    except Exception as e:
        print("\nExpiry mailer failed:")
        print(e)
        die(1)

def test_revoke_by_account():
    cert_file_pem = os.path.join(tempdir, "revokeme.pem")
    client = chisel.make_client()
    cert = auth_and_issue([random_domain()], client=client).body
    client.revoke(cert.body)

    wait_for_ocsp_revoked(cert_file_pem, "test/test-ca2.pem", ee_ocsp_url)
    return 0

def test_caa():
    """Request issuance for two CAA domains, one where we are permitted and one where we are not."""
    auth_and_issue(["good-caa-reserved.com"])

    # TODO(#2514): Currently, the gRPC setup doesn't correctly set the error
    # field on failed validations. Once #2514 is fixed, remove this if statement.
    if os.getenv('BOULDER_CONFIG_DIR') != 'test/config-next':
        chisel.expect_problem("urn:acme:error:connection",
            lambda: auth_and_issue(["bad-caa-reserved.com"]))

def run_custom(cmd, cwd=None):
    if subprocess.Popen(cmd, shell=True, cwd=cwd, executable='/bin/bash').wait() != 0:
        die(ExitStatus.PythonFailure)

def run_client_tests():
    root = os.environ.get("CERTBOT_PATH")
    assert root is not None, (
        "Please set CERTBOT_PATH env variable to point at "
        "initialized (virtualenv) client repo root")
    cmd = os.path.join(root, 'tests', 'boulder-integration.sh')
    run_custom(cmd, cwd=root)

# Run the single-ocsp command, which is used to generate OCSP responses for
# intermediate certificates on a manual basis.
def single_ocsp_sign():
    try:
        subprocess.check_output("""./bin/single-ocsp -issuer test/test-root.pem \
                    -responder test/test-root.pem \
                    -target test/test-ca2.pem \
                    -pkcs11 test/test-root.key-pkcs11.json \
                    -thisUpdate 2016-09-02T00:00:00Z \
                    -nextUpdate 2020-09-02T00:00:00Z \
                    -status 0 \
                    -out /tmp/issuer-ocsp-responses.txt""", shell=True)
    except subprocess.CalledProcessError as e:
        print("\nFailed to run single-ocsp: %s" % e)
        die(ExitStatus.PythonFailure)

    p = subprocess.Popen(
        './bin/ocsp-responder --config test/issuer-ocsp-responder.json', shell=True)

    # Verify that the static OCSP responder, which answers with a
    # pre-signed, long-lived response for the CA cert, works.
    wait_for_ocsp_good("test/test-ca2.pem", "test/test-root.pem", "http://localhost:4003")

    p.send_signal(signal.SIGTERM)

def get_future_output(cmd, date, cwd=None):
    return subprocess.check_output(cmd, cwd=cwd, env={'FAKECLOCK': date.strftime("%a %b %d %H:%M:%S UTC %Y")}, shell=True)

def test_expired_authz_purger():
    # Make an authz, but don't attempt its challenges.
    chisel.make_client().request_domain_challenges("eap-test.com")

    def expect(target_time, num):
        expected_output = 'Deleted a total of %d expired pending authorizations' % num
        try:
            out = get_future_output("./bin/expired-authz-purger --config cmd/expired-authz-purger/config.json --yes", target_time)
            if expected_output not in out:
                print("\nOutput from expired-authz-purger did not contain '%s'. Actual: %s"
                    % (expected_output, out))
                die(ExitStatus.NodeFailure)
        except subprocess.CalledProcessError as e:
            print("\nFailed to run authz purger: %s" % e)
            die(ExitStatus.NodeFailure)

    now = datetime.datetime.utcnow()
    after_grace_period = now + datetime.timedelta(days=+14, minutes=+3)
    expect(now, 0)
    expect(after_grace_period, 1)

def test_certificates_per_name():
    chisel.expect_problem("urn:acme:error:rateLimited",
        lambda: auth_and_issue(["lim.it"]))

default_config_dir = os.environ.get('BOULDER_CONFIG_DIR', '')
if default_config_dir == '':
    default_config_dir = 'test/config'

def test_admin_revoker_cert():
    cert_file_pem = os.path.join(tempdir, "ar-cert.pem")
    cert = auth_and_issue([random_domain()], cert_output=cert_file_pem).body
    serial = "%x" % cert.get_serial_number()
    # Revoke certificate by serial
    if subprocess.Popen(
        "./bin/admin-revoker serial-revoke --config %s/admin-revoker.json %s %d" % (
                default_config_dir, serial, 1), shell=True).wait() != 0:
        print("Failed to revoke certificate")
        die(ExitStatus.RevokerFailure)
    # Wait for OCSP response to indicate revocation took place
    ee_ocsp_url = "http://localhost:4002"
    wait_for_ocsp_revoked(cert_file_pem, "test/test-ca2.pem", ee_ocsp_url)

def test_admin_revoker_authz():
    # Make an authz, but don't attempt its challenges.
    authz_resource = chisel.make_client().request_domain_challenges("ar-auth-test.com")
    url = authz_resource.uri
    # Revoke authorization by domain
    try:
        output = subprocess.check_output(
                "./bin/admin-revoker auth-revoke --config %s/admin-revoker.json ar-auth-test.com" % (default_config_dir), shell=True)
    except subprocess.CalledProcessError as e:
        print("Failed to revoke authorization: %s", e)
        die(ExitStatus.RevokerFailure)
    if not output.rstrip().endswith("Revoked 1 pending authorizations and 0 final authorizations"):
        print("admin-revoker didn't revoke the expected number of pending and finalized authorizations")
        die(ExitStatus.RevokerFailure)
    # Check authorization has actually been revoked
    response = urllib2.urlopen(url)
    data = json.loads(response.read())
    if data['status'] != "revoked":
        print("Authorization wasn't revoked")
        die(ExitStatus.RevokerFailure)

exit_status = None
tempdir = tempfile.mkdtemp()

def main():
    parser = argparse.ArgumentParser(description='Run integration tests')
    parser.add_argument('--all', dest="run_all", action="store_true",
                        help="run all of the clients' integration tests")
    parser.add_argument('--certbot', dest='run_certbot', action='store_true',
                        help="run the certbot integration tests")
    parser.add_argument('--chisel', dest="run_chisel", action="store_true",
                        help="run integration tests using chisel")
    # allow any ACME client to run custom command for integration
    # testing (without having to implement its own busy-wait loop)
    parser.add_argument('--custom', metavar="CMD", help="run custom command")
    parser.set_defaults(run_all=False, run_certbot=False, run_node=False)
    args = parser.parse_args()

    if not (args.run_all or args.run_certbot or args.run_chisel or args.custom is not None):
        print >> sys.stderr, "must run at least one of the letsencrypt or node tests with --all, --certbot, --chisel, or --custom"
        die(ExitStatus.IncorrectCommandLineArgs)

    # Keep track of whether we started the Boulder servers and need to shut them down.
    started_servers = False
    # Check if WFE is already running.
    try:
        urllib2.urlopen("http://localhost:4000/directory")
    except urllib2.URLError:
        # WFE not running, start all of Boulder.
        started_servers = True
        if not startservers.start(race_detection=True):
            die(ExitStatus.Error)

    if args.run_all or args.run_chisel:
        run_chisel()

    # Simulate a disconnection from RabbitMQ to make sure reconnects work.
    if started_servers:
        startservers.bounce_forward()

    if args.run_all or args.run_certbot:
        run_client_tests()

    if args.custom:
        run_custom(args.custom)

    if started_servers and not startservers.check():
        die(ExitStatus.Error)
    exit_status = ExitStatus.OK

def run_chisel():
    # XXX: Test multiple challenge types

    test_gsb_lookups()
    test_expired_authz_purger()
    test_multidomain()
    test_expiration_mailer()
    test_ct_submission()
    test_caa()
    test_admin_revoker_cert()
    test_admin_revoker_authz()
    test_certificates_per_name()
    test_ocsp()
    single_ocsp_sign()

if __name__ == "__main__":
    try:
        main()
    except Exception:
        exit_status = ExitStatus.Error
        raise

@atexit.register
def stop():
    import shutil
    shutil.rmtree(tempdir)
    if exit_status == ExitStatus.OK:
        print("\n\nSUCCESS")
    else:
        if exit_status:
            print("\n\nFAILURE %d" % exit_status)
