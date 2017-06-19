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

class ProcInfo:
    """
        Args:
            cmd (str): The command that was run
            proc(subprocess.Popen): The Popen of the command run
    """

    def __init__(self, cmd, proc):
        self.cmd = cmd
        self.proc = proc

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
    run("openssl ocsp -no_nonce -issuer %s -cert %s -reqout %s" % (
        issuer_file, cert_file, ocsp_req_file))
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
            raise Exception("Timed out waiting for OCSP to go from '%s' to '%s'" % (
                initial, final))
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
                raise Exception("OCSP response didn't match '%s' or '%s'" %(
                    initial, final))
        if all_final:
            # Check that all responses were equal to each other.
            for resp in responses:
                if resp != responses[0]:
                    raise Exception("OCSP responses differed: %s vs %s" %(
                        base64.b64encode(responses[0]), base64.b64encode(resp)))
            return

def ocsp_verify(cert_file, issuer_file, ocsp_response):
    ocsp_resp_file = os.path.join(tempdir, "ocsp.resp")
    with open(ocsp_resp_file, "w") as f:
        f.write(ocsp_response)
    output = run("openssl ocsp -no_nonce -issuer %s -cert %s \
      -verify_other %s -CAfile test/test-root.pem \
      -respin %s" % (issuer_file, cert_file, issuer_file, ocsp_resp_file))
    # OpenSSL doesn't always return non-zero when response verify fails, so we
    # also look for the string "Response Verify Failure"
    verify_failure = "Response Verify Failure"
    if re.search(verify_failure, output):
        print output
        raise Exception("OCSP verify failure")
    return output

def wait_for_ocsp_good(cert_file, issuer_file, url):
    fetch_until(cert_file, issuer_file, url, " unauthorized", ": good")

def wait_for_ocsp_revoked(cert_file, issuer_file, url):
    fetch_until(cert_file, issuer_file, url, ": good", ": revoked")

def test_multidomain():
    auth_and_issue([random_domain(), random_domain()])

def test_dns_challenge():
    auth_and_issue([random_domain(), random_domain()], chall_type="dns-01")

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
    # When testing config-next we use a mismatching set of CT logs in the boulder-publisher
    # and ocsp-updater configuration files. The ocsp-updater config has an extra log which the
    # publisher does not. When the publisher does the initial submission it will only submit
    # the certificate to a single log, when the ocsp-updater then runs looking for missing SCTs
    # it will think we failed to retrieve an SCT for the extra log it is configured with and
    # attempt to submit it to just that log instead of all of the logs it knows about (which
    # is just the one it already has submitted to).
    url_a = "http://boulder:4500/submissions"
    url_b = "http://boulder:4501/submissions"
    submissions_a = urllib2.urlopen(url_a).read()
    submissions_b = urllib2.urlopen(url_b).read()
    expected_a_submissions = int(submissions_a)+1
    expected_b_submissions = int(submissions_b)+1
    auth_and_issue([random_domain()])
    submissions_a = urllib2.urlopen(url_a).read()
    # Presently the CA and the ocsp-updater can race on the initial submission
    # of a certificate to the configured logs. This results in over submitting
    # certificates. This is expected to be fixed in the future by a planned
    # redesign so for now we do not error when the number of submissions falls
    # between the expected value and two times the expected. See Boulder #2610
    # for more information: https://github.com/letsencrypt/boulder/issues/2610
    if (int(submissions_a) < expected_a_submissions or
        int(submissions_a) > 2 * expected_a_submissions):
        raise Exception("Expected %d CT submissions to boulder:4500, found %s" % (expected_a_submissions, submissions_a))
    # Only test when ResubmitMissingSCTsOnly is enabled
    if not default_config_dir.startswith("test/config-next"):
        return
    for _ in range(0, 10):
        submissions_a = urllib2.urlopen(url_a).read()
        submissions_b = urllib2.urlopen(url_b).read()
        if (int(submissions_a) < expected_a_submissions or
            int(submissions_a) > 2 * expected_a_submissions):
            raise Exception("Expected no change in submissions to boulder:4500: expected %s, got %s" % (expected_a_submissions, submissions_a))
        if (int(submissions_b) >= expected_b_submissions and
            int(submissions_b) < 2 * expected_b_submissions + 1):
            return
        time.sleep(1)
    raise Exception("Expected %d CT submissions to boulder:4501, found %s" % (expected_b_submissions, submissions_b))


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
        raise("\nExpiry mailer failed: expected 2 emails, got %d" % mailcount)

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

    chisel.expect_problem("urn:acme:error:connection",
        lambda: auth_and_issue(["bad-caa-reserved.com"]))

def run(cmd, **kwargs):
    return subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, **kwargs)

def run_client_tests():
    root = os.environ.get("CERTBOT_PATH")
    assert root is not None, (
        "Please set CERTBOT_PATH env variable to point at "
        "initialized (virtualenv) client repo root")
    cmd = os.path.join(root, 'tests', 'boulder-integration.sh')
    run(cmd, cwd=root)

def test_single_ocsp():
    """Run the single-ocsp command, which is used to generate OCSP responses for
       intermediate certificates on a manual basis. Then start up an
       ocsp-responder configured to respond using the output of single-ocsp,
       check that it successfully answers OCSP requests, and shut the responder
       back down.
    """
    run("./bin/single-ocsp -issuer test/test-root.pem \
            -responder test/test-root.pem \
            -target test/test-ca2.pem \
            -pkcs11 test/test-root.key-pkcs11.json \
            -thisUpdate 2016-09-02T00:00:00Z \
            -nextUpdate 2020-09-02T00:00:00Z \
            -status 0 \
            -out /tmp/issuer-ocsp-responses.txt")

    p = subprocess.Popen(
        './bin/ocsp-responder --config test/issuer-ocsp-responder.json', shell=True)

    # Verify that the static OCSP responder, which answers with a
    # pre-signed, long-lived response for the CA cert, works.
    wait_for_ocsp_good("test/test-ca2.pem", "test/test-root.pem", "http://localhost:4003")

    p.send_signal(signal.SIGTERM)
    p.wait()

def get_future_output(cmd, date):
    return run(cmd, env={'FAKECLOCK': date.strftime("%a %b %d %H:%M:%S UTC %Y")})

def test_expired_authz_purger():
    def expect(target_time, num, table):
        out = get_future_output("./bin/expired-authz-purger --config cmd/expired-authz-purger/config.json --yes", target_time)
        if 'via FAKECLOCK' not in out:
            raise Exception("expired-authz-purger was not built with `integration` build tag")
        if num is None:
            return
        expected_output = 'Deleted a total of %d expired authorizations from %s' % (num, table)
        if expected_output not in out:
            raise Exception("expired-authz-purger did not print '%s'.  Output:\n%s" % (
                  expected_output, out))

    now = datetime.datetime.utcnow()

    # Run the purger once to clear out any backlog so we have a clean slate.
    expect(now+datetime.timedelta(days=+365), None, "")

    # Make an authz, but don't attempt its challenges.
    chisel.make_client().request_domain_challenges("eap-test.com")

    # Run the authz twice: Once immediate, expecting nothing to be purged, and
    # once as if it were the future, expecting one purged authz.
    after_grace_period = now + datetime.timedelta(days=+14, minutes=+3)
    expect(now, 0, "pendingAuthorizations")
    expect(after_grace_period, 1, "pendingAuthorizations")

    auth_and_issue([random_domain()])
    after_grace_period = now + datetime.timedelta(days=+67, minutes=+3)
    expect(now, 0, "authz")
    expect(after_grace_period, 1, "authz")

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
    run("./bin/admin-revoker serial-revoke --config %s/admin-revoker.json %s %d" % (
        default_config_dir, serial, 1))
    # Wait for OCSP response to indicate revocation took place
    ee_ocsp_url = "http://localhost:4002"
    wait_for_ocsp_revoked(cert_file_pem, "test/test-ca2.pem", ee_ocsp_url)

def test_admin_revoker_authz():
    # Make an authz, but don't attempt its challenges.
    authz_resource = chisel.make_client().request_domain_challenges("ar-auth-test.com")
    url = authz_resource.uri
    # Revoke authorization by domain
    output = run(
            "./bin/admin-revoker auth-revoke --config %s/admin-revoker.json ar-auth-test.com" % (default_config_dir))
    if not output.rstrip().endswith("Revoked 1 pending authorizations and 0 final authorizations"):
        raise Exception("admin-revoker didn't revoke the expected number of pending and finalized authorizations")
    # Check authorization has actually been revoked
    response = urllib2.urlopen(url)
    data = json.loads(response.read())
    if data['status'] != "revoked":
        raise Exception("Authorization wasn't revoked")

exit_status = 1
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
    parser.set_defaults(run_all=False, run_certbot=False, run_chisel=False)
    args = parser.parse_args()

    if not (args.run_all or args.run_certbot or args.run_chisel or args.custom is not None):
        raise Exception("must run at least one of the letsencrypt or chisel tests with --all, --certbot, --chisel, or --custom")

    # Keep track of whether we started the Boulder servers and need to shut them down.
    started_servers = False
    # Check if WFE is already running.
    try:
        urllib2.urlopen("http://localhost:4000/directory")
    except urllib2.URLError:
        # WFE not running, start all of Boulder.
        started_servers = True
        if not startservers.start(race_detection=True):
            raise Exception("startservers failed")

    if args.run_all or args.run_chisel:
        run_chisel()

    # Simulate a disconnection from RabbitMQ to make sure reconnects work.
    if started_servers:
        startservers.bounce_forward()

    if args.run_all or args.run_certbot:
        run_client_tests()

    if args.custom:
        run(args.custom)

    if started_servers and not startservers.check():
        raise Exception("startservers.check failed")

    global exit_status
    exit_status = 0

def run_chisel():
    # TODO(https://github.com/letsencrypt/boulder/issues/2521): Add TLS-SNI test.

    test_expired_authz_purger()
    test_ct_submission()
    test_gsb_lookups()
    test_multidomain()
    test_expiration_mailer()
    test_caa()
    test_admin_revoker_cert()
    test_admin_revoker_authz()
    test_certificates_per_name()
    test_ocsp()
    test_single_ocsp()
    test_dns_challenge()

if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as e:
        raise Exception("%s. Output:\n%s" % (e, e.output))

@atexit.register
def stop():
    import shutil
    shutil.rmtree(tempdir)
    if exit_status == 0:
        print("\n\nSUCCESS")
    else:
        print("\n\nFAILURE")
