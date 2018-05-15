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
import requests
import shutil
import subprocess
import signal
import struct
import sys
import tempfile
import time
import urllib2

import startservers

import chisel
from chisel import auth_and_issue
from v2_integration import *

import requests
import OpenSSL

from cryptography import x509
from cryptography.hazmat.backends import default_backend

class ProcInfo:
    """
        Args:
            cmd (str): The command that was run
            proc(subprocess.Popen): The Popen of the command run
    """

    def __init__(self, cmd, proc):
        self.cmd = cmd
        self.proc = proc

caa_client = None
caa_authzs = []
old_authzs = []
new_authzs = []

def setup_seventy_days_ago():
    """Do any setup that needs to happen 70 days in the past, for tests that
       will run in the 'present'.
    """
    # Issue a certificate with the clock set back, and save the authzs to check
    # later that they are expired (404).
    global old_authzs
    _, old_authzs = auth_and_issue([random_domain()])

def setup_twenty_days_ago():
    """Do any setup that needs to happen 20 day in the past, for tests that
       will run in the 'present'.
    """
    # Issue a certificate with the clock set back, and save the authzs to check
    # later that they are valid (200). They should however require rechecking for
    # CAA purposes.
    global caa_client
    caa_client = chisel.make_client()
    global caa_authzs
    _, caa_authzs = auth_and_issue(["recheck.good-caa-reserved.com"], client=caa_client)

def setup_zero_days_ago():
    """Do any setup that needs to happen at the start of a test run."""
    # Issue a certificate and save the authzs to check that they still exist
    # at a later point.
    global new_authzs
    _, new_authzs = auth_and_issue([random_domain()])

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

def test_http_challenge():
    auth_and_issue([random_domain(), random_domain()], chall_type="http-01")

def test_issuer():
    """
    Issue a certificate, fetch its chain, and verify the chain and
    certificate against test/test-root.pem. Note: This test only handles chains
    of length exactly 1.
    """
    certr, authzs = auth_and_issue([random_domain()])
    cert = urllib2.urlopen(certr.uri).read()
    # The chain URI uses HTTPS when UseAIAIssuerURL is set, so include the root
    # certificate for the WFE's PKI. Note: We use the requests library here so
    # we honor the REQUESTS_CA_BUNDLE passed by test.sh.
    chain = requests.get(certr.cert_chain_uri).content
    parsed_chain = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, chain)
    parsed_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert)
    parsed_root = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM,
        open("test/test-root.pem").read())

    store = OpenSSL.crypto.X509Store()
    store.add_cert(parsed_root)

    # Check the chain certificate before adding it to the store.
    store_ctx = OpenSSL.crypto.X509StoreContext(store, parsed_chain)
    store_ctx.verify_certificate()
    store.add_cert(parsed_chain)

    # Now check the end-entity certificate.
    store_ctx = OpenSSL.crypto.X509StoreContext(store, parsed_cert)
    store_ctx.verify_certificate()

def test_gsb_lookups():
    """Attempt issuances for a GSB-blocked domain, and expect it to fail. Also
       check the gsb-test-srv's count of received queries to ensure it got a
       request."""
    hostname = "honest.achmeds.discount.hosting.com"
    chisel.expect_problem("urn:acme:error:unauthorized",
        lambda: auth_and_issue([hostname]))

    hits_map = json.loads(urllib2.urlopen("http://localhost:6000/hits").read())

    # The GSB test server tracks hits with a trailing / on the URL
    hits = hits_map.get(hostname + "/", 0)
    if hits != 1:
        raise Exception("Expected %d Google Safe Browsing lookups for %s, found %d" % (1, url, actual))

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
    cert, _ = auth_and_issue([random_domain()], email=email_addr)
    # Check that the expiration mailer sends a reminder
    expiry = datetime.datetime.strptime(cert.body.get_notAfter(), '%Y%m%d%H%M%SZ')
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
        raise Exception("\nExpiry mailer failed: expected 2 emails, got %d" % mailcount)

def test_revoke_by_account():
    client = chisel.make_client()
    cert, _ = auth_and_issue([random_domain()], client=client)
    client.revoke(cert.body, 0)

    cert_file_pem = os.path.join(tempdir, "revokeme.pem")
    with open(cert_file_pem, "w") as f:
        f.write(OpenSSL.crypto.dump_certificate(
            OpenSSL.crypto.FILETYPE_PEM, cert.body.wrapped).decode())
    ee_ocsp_url = "http://localhost:4002"
    wait_for_ocsp_revoked(cert_file_pem, "test/test-ca2.pem", ee_ocsp_url)
    return 0

def test_caa():
    """Request issuance for two CAA domains, one where we are permitted and one where we are not.
       Two further sub-domains have restricted validation-methods.
    """
    if len(caa_authzs) == 0:
        raise Exception("CAA authzs not prepared for test_caa")
    for a in caa_authzs:
        response = requests.get(a.uri)
        if response.status_code != 200:
            raise Exception("Unexpected response for CAA authz: ",
                response.status_code)

    auth_and_issue(["good-caa-reserved.com"])

    # Request issuance for recheck.good-caa-reserved.com, which should
    # now be denied due to CAA.
    chisel.expect_problem("urn:acme:error:caa", lambda: chisel.issue(caa_client, caa_authzs))

    chisel.expect_problem("urn:acme:error:caa",
        lambda: auth_and_issue(["bad-caa-reserved.com"]))

    chisel.expect_problem("urn:acme:error:caa",
        lambda: auth_and_issue(["dns-01-only.good-caa-reserved.com"], chall_type="http-01"))

    chisel.expect_problem("urn:acme:error:caa",
        lambda: auth_and_issue(["http-01-only.good-caa-reserved.com"], chall_type="dns-01"))

    # Note: the additional names are to avoid rate limiting...
    global caa_client
    auth_and_issue(["dns-01-only.good-caa-reserved.com", "www.dns-01-only.good-caa-reserved.com"], chall_type="dns-01")
    auth_and_issue(["http-01-only.good-caa-reserved.com", "www.http-01-only.good-caa-reserved.com"], chall_type="http-01")

def test_account_update():
    """
    Create a new ACME client/account with one contact email. Then update the
    account to a different contact emails.
    """
    emails=("initial-email@example.com", "updated-email@example.com", "another-update@example.com")
    client = chisel.make_client(email=emails[0])

    for email in emails[1:]:
        result = chisel.update_email(client, email=email)
        # We expect one contact in the result
        if len(result.body.contact) != 1:
            raise Exception("\nUpdate account failed: expected one contact in result, got 0")
        # We expect it to be the email we just updated to
        actual = result.body.contact[0]
        if actual != "mailto:"+email:
            raise Exception("\nUpdate account failed: expected contact %s, got %s" % (email, actual))

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

def fakeclock(date):
    return date.strftime("%a %b %d %H:%M:%S UTC %Y")

def get_future_output(cmd, date):
    return run(cmd, env={'FAKECLOCK': fakeclock(date)})

def run_expired_authz_purger():
    # Note: This test must be run after all other tests that depend on
    # authorizations added to the database during setup
    # (e.g. test_expired_authzs_404).

    def expect(target_time, num, table):
        out = get_future_output("./bin/expired-authz-purger --config cmd/expired-authz-purger/config.json", target_time)
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

def test_renewal_exemption():
    """
    Under a single domain, issue one certificate, then two renewals of that
    certificate, then one more different certificate (with a different
    subdomain). Since the certificatesPerName rate limit in testing is 2 per 90
    days, and the renewals should be discounted under the renewal exemption,
    each of these issuances should succeed. Then do one last issuance that we
    expect to be rate limited, just to check that the rate limit is actually 2,
    and we are testing what we think we are testing. See
    https://letsencrypt.org/docs/rate-limits/ for more details.
    """

    # TODO(@cpu): Once the `AllowRenewalFirstRL` feature flag is enabled by
    # default, delete this early return.
    if not default_config_dir.startswith("test/config-next"):
        return

    base_domain = random_domain()
    # First issuance
    auth_and_issue(["www." + base_domain])
    # First Renewal
    auth_and_issue(["www." + base_domain])
    # Second Renewal
    auth_and_issue(["www." + base_domain])
    # Issuance of a different cert
    auth_and_issue(["blog." + base_domain])
    # Final, failed issuance, for another different cert
    chisel.expect_problem("urn:acme:error:rateLimited",
        lambda: auth_and_issue(["mail." + base_domain]))

def test_certificates_per_name():
    chisel.expect_problem("urn:acme:error:rateLimited",
        lambda: auth_and_issue([random_domain() + ".lim.it"]))

def test_expired_authzs_404():
    # TODO(@4a6f656c): This test is rather broken, since it cannot distinguish
    # between a 404 due to an expired authz and a 404 due to a non-existant authz.
    # Further verification is necessary in order to ensure that the 404 is actually
    # due to an expiration. For now, the new authzs at least provide a form of
    # canary to detect authz purges.
    if len(old_authzs) == 0 or len(new_authzs) == 0:
        raise Exception("Old authzs not prepared for test_expired_authzs_404")
    for a in new_authzs:
        response = requests.get(a.uri)
        if response.status_code != 200:
            raise Exception("Unexpected response for valid authz: ",
                response.status_code)
    for a in old_authzs:
        response = requests.get(a.uri)
        if response.status_code != 404:
            raise Exception("Unexpected response for expired authz: ",
                response.status_code)

def test_oversized_csr():
    # Number of names is chosen to be one greater than the configured RA/CA maxNames
    numNames = 101
    # Generate numNames subdomains of a random domain
    base_domain = random_domain()
    domains = [ "{0}.{1}".format(str(n),base_domain) for n in range(numNames) ]
    # We expect issuing for these domains to produce a malformed error because
    # there are too many names in the request.
    chisel.expect_problem("urn:acme:error:malformed",
            lambda: auth_and_issue(domains))

default_config_dir = os.environ.get('BOULDER_CONFIG_DIR', '')
if default_config_dir == '':
    default_config_dir = 'test/config'

def test_admin_revoker_cert():
    cert_file_pem = os.path.join(tempdir, "ar-cert.pem")
    cert, _ = auth_and_issue([random_domain()], cert_output=cert_file_pem)
    serial = "%x" % cert.body.get_serial_number()
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

def test_stats():
    def expect_stat(port, stat):
        url = "http://localhost:%d/metrics" % port
        response = requests.get(url)
        if not stat in response.content:
            print(response.content)
            raise Exception("%s not present in %s" % (stat, url))
    expect_stat(8000, "\nresponse_time_count{")
    expect_stat(8000, "\ngo_goroutines ")
    expect_stat(8000, '\ngrpc_client_handling_seconds_count{grpc_method="NewRegistration",grpc_service="ra.RegistrationAuthority",grpc_type="unary"} ')
    expect_stat(8002, '\ngrpc_server_handling_seconds_sum{grpc_method="UpdateAuthorization",grpc_service="ra.RegistrationAuthority",grpc_type="unary"} ')
    expect_stat(8002, '\ngrpc_client_handling_seconds_count{grpc_method="UpdatePendingAuthorization",grpc_service="sa.StorageAuthority",grpc_type="unary"} ')
    expect_stat(8001, "\ngo_goroutines ")

def test_sct_embedding():
    if not os.environ.get('BOULDER_CONFIG_DIR', '').startswith("test/config-next"):
        return
    certr, authzs = auth_and_issue([random_domain()])
    certBytes = urllib2.urlopen(certr.uri).read()
    cert = x509.load_der_x509_certificate(certBytes, default_backend())

    # make sure there is no poison extension
    try:
        cert.extensions.get_extension_for_oid(x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.4.3"))
        raise Exception("certificate contains CT poison extension")
    except x509.ExtensionNotFound:
        # do nothing
        pass

    # make sure there is a SCT list extension
    try:
        sctList = cert.extensions.get_extension_for_oid(x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.4.2"))
    except x509.ExtensionNotFound:
        raise Exception("certificate doesn't contain SCT list extension")
    if len(sctList.value) != 2:
        raise Exception("SCT list contains wrong number of SCTs")
    for sct in sctList.value:
        if sct.version != x509.certificate_transparency.Version.v1:
            raise Exception("SCT contains wrong version")
        if sct.entry_type != x509.certificate_transparency.LogEntryType.PRE_CERTIFICATE:
            raise Exception("SCT contains wrong entry type")
        delta = sct.timestamp - datetime.datetime.now()
        if abs(delta) > datetime.timedelta(hours=1):
            raise Exception("Delta between SCT timestamp and now was too great "
                "%s vs %s (%s)" % (sct.timestamp, datetime.datetime.now(), delta))

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
    parser.add_argument('--load', dest="run_loadtest", action="store_true",
                        help="run load-generator")
    parser.add_argument('--filter', dest="test_case_filter", action="store",
                        help="Regex filter for test cases")
    # allow any ACME client to run custom command for integration
    # testing (without having to implement its own busy-wait loop)
    parser.add_argument('--custom', metavar="CMD", help="run custom command")
    parser.set_defaults(run_all=False, run_certbot=False, run_chisel=False,
        run_loadtest=False, test_case_filter="")
    args = parser.parse_args()

    if not (args.run_all or args.run_certbot or args.run_chisel or args.run_loadtest or args.custom is not None):
        raise Exception("must run at least one of the letsencrypt or chisel tests with --all, --certbot, --chisel, --load or --custom")

    now = datetime.datetime.utcnow()
    seventy_days_ago = now+datetime.timedelta(days=-70)
    if not startservers.start(race_detection=True, fakeclock=fakeclock(seventy_days_ago)):
        raise Exception("startservers failed (mocking seventy days ago)")
    setup_seventy_days_ago()
    startservers.stop()

    now = datetime.datetime.utcnow()
    twenty_days_ago = now+datetime.timedelta(days=-20)
    if not startservers.start(race_detection=True, fakeclock=fakeclock(twenty_days_ago)):
        raise Exception("startservers failed (mocking twenty days ago)")
    setup_twenty_days_ago()
    startservers.stop()

    if not startservers.start(race_detection=True):
        raise Exception("startservers failed")

    setup_zero_days_ago()

    if args.run_all or args.run_chisel:
        run_chisel(args.test_case_filter)

    if args.run_all or args.run_certbot:
        run_client_tests()

    if args.run_all or args.run_loadtest:
        run_loadtest()

    if args.custom:
        run(args.custom)

    run_cert_checker()
    run_expired_authz_purger()

    if not startservers.check():
        raise Exception("startservers.check failed")

    global exit_status
    exit_status = 0

def run_chisel(test_case_filter):
    for key, value in globals().items():
      if callable(value) and key.startswith('test_') and re.search(test_case_filter, key):
        value()

def run_loadtest():
    """Run the load generator for v1 and v2."""
    latency_data_file = "%s/integration-test-latency.json" % tempdir
    run("./bin/load-generator \
            -config test/load-generator/config/integration-test-config.json\
            -results %s" % latency_data_file)

    latency_data_file = "%s/v2-integration-test-latency.json" % tempdir
    run("./bin/load-generator \
            -config test/load-generator/config/v2-integration-test-config.json\
            -results %s" % latency_data_file)

def run_cert_checker():
    run("./bin/cert-checker -config %s/cert-checker.json" % default_config_dir)

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
