#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-
import datetime
import json
import os
import random
import re
import requests
import time
import urllib2

import startservers

import chisel
from chisel import auth_and_issue
from helpers import *

from acme import challenges

import OpenSSL

from cryptography import x509
from cryptography.hazmat.backends import default_backend

import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

import challtestsrv
challSrv = challtestsrv.ChallTestServer()

def test_dns_challenge():
    auth_and_issue([random_domain(), random_domain()], chall_type="dns-01")

def test_http_challenge():
    auth_and_issue([random_domain(), random_domain()], chall_type="http-01")

def rand_http_chall(client):
    d = random_domain()
    authz = client.request_domain_challenges(d)
    for c in authz.body.challenges:
        if isinstance(c.chall, challenges.HTTP01):
            return d, c.chall
    raise Exception("No HTTP-01 challenge found for random domain authz")

def test_http_challenge_loop_redirect():
    client = chisel.make_client()

    # Create an authz for a random domain and get its HTTP-01 challenge token
    d, chall = rand_http_chall(client)
    token = chall.encode("token")

    # Create a HTTP redirect from the challenge's validation path to itself
    challengePath = "/.well-known/acme-challenge/{0}".format(token)
    challSrv.add_http_redirect(
        challengePath,
        "http://{0}{1}".format(d, challengePath))

    # Issuing for the the name should fail because of the challenge domains's
    # redirect loop.
    chisel.expect_problem("urn:acme:error:connection",
        lambda: auth_and_issue([d], client=client, chall_type="http-01"))

    challSrv.remove_http_redirect(challengePath)

def test_http_challenge_badport_redirect():
    client = chisel.make_client()

    # Create an authz for a random domain and get its HTTP-01 challenge token
    d, chall = rand_http_chall(client)
    token = chall.encode("token")

    # Create a HTTP redirect from the challenge's validation path to a host with
    # an invalid port.
    challengePath = "/.well-known/acme-challenge/{0}".format(token)
    challSrv.add_http_redirect(
        challengePath,
        "http://{0}:1337{1}".format(d, challengePath))

    # Issuing for the name should fail because of the challenge domain's
    # invalid port redirect.
    chisel.expect_problem("urn:acme:error:connection",
        lambda: auth_and_issue([d], client=client, chall_type="http-01"))

    challSrv.remove_http_redirect(challengePath)

def test_http_challenge_badhost_redirect():
    client = chisel.make_client()

    # Create an authz for a random domain and get its HTTP-01 challenge token
    d, chall = rand_http_chall(client)
    token = chall.encode("token")

    # Create a HTTP redirect from the challenge's validation path to a bare IP
    # hostname.
    challengePath = "/.well-known/acme-challenge/{0}".format(token)
    challSrv.add_http_redirect(
        challengePath,
        "https://127.0.0.1{0}".format(challengePath))

    # Issuing for the name should cause a connection error because the redirect
    # domain name is an IP address.
    chisel.expect_problem("urn:acme:error:connection",
        lambda: auth_and_issue([d], client=client, chall_type="http-01"))

    challSrv.remove_http_redirect(challengePath)

def test_http_challenge_badproto_redirect():
    client = chisel.make_client()

    # Create an authz for a random domain and get its HTTP-01 challenge token
    d, chall = rand_http_chall(client)
    token = chall.encode("token")

    # Create a HTTP redirect from the challenge's validation path to whacky
    # non-http/https protocol URL.
    challengePath = "/.well-known/acme-challenge/{0}".format(token)
    challSrv.add_http_redirect(
        challengePath,
        "gopher://{0}{1}".format(d, challengePath))

    # Issuing for the name should cause a connection error because the redirect
    # URL an invalid protocol scheme.
    chisel.expect_problem("urn:acme:error:connection",
        lambda: auth_and_issue([d], client=client, chall_type="http-01"))

    challSrv.remove_http_redirect(challengePath)

def test_http_challenge_http_redirect():
    client = chisel.make_client()

    # Create an authz for a random domain and get its HTTP-01 challenge token
    d, chall = rand_http_chall(client)
    token = chall.encode("token")
    # Calculate its keyauth so we can add it in a special non-standard location
    # for the redirect result
    resp = chall.response(client.key)
    keyauth = resp.key_authorization
    challSrv.add_http01_response("http-redirect", keyauth)

    # Create a HTTP redirect from the challenge's validation path to some other
    # token path where we have registered the key authorization.
    challengePath = "/.well-known/acme-challenge/{0}".format(token)
    redirectPath = "/.well-known/acme-challenge/http-redirect?params=are&important=to&not=lose"
    challSrv.add_http_redirect(
        challengePath,
        "http://{0}{1}".format(d, redirectPath))

    # Issuing should succeed
    auth_and_issue([d], client=client, chall_type="http-01")

    # Cleanup the redirects
    challSrv.remove_http_redirect(challengePath)
    challSrv.remove_http01_response("http-redirect")

    history = challSrv.http_request_history(d)
    challSrv.clear_http_request_history(d)

    # There should have been at least two GET requests made to the
    # challtestsrv. There may have been more if remote VAs were configured.
    if len(history) < 2:
        raise Exception("Expected at least 2 HTTP request events on challtestsrv, found {1}".format(len(history)))

    initialRequests = []
    redirectedRequests = []

    for request in history:
      # All requests should have been over HTTP
      if request['HTTPS'] is True:
        raise Exception("Expected all requests to be HTTP")
      # Initial requests should have the expected initial HTTP-01 URL for the challenge
      if request['URL'] == challengePath:
        initialRequests.append(request)
      # Redirected requests should have the expected redirect path URL with all
      # its parameters
      elif request['URL'] == redirectPath:
        redirectedRequests.append(request)
      else:
        raise Exception("Unexpected request URL {0} in challtestsrv history: {1}".format(request['URL'], request))

    # There should have been at least 1 initial HTTP-01 validation request.
    if len(initialRequests) < 1:
        raise Exception("Expected {0} initial HTTP-01 request events on challtestsrv, found {1}".format(validation_attempts, len(initialRequests)))

    # There should have been at least 1 redirected HTTP request for each VA
    if len(redirectedRequests) < 1:
        raise Exception("Expected {0} redirected HTTP-01 request events on challtestsrv, found {1}".format(validation_attempts, len(redirectedRequests)))

def test_http_challenge_https_redirect():
    client = chisel.make_client()

    # Create an authz for a random domain and get its HTTP-01 challenge token
    d, chall = rand_http_chall(client)
    token = chall.encode("token")
    # Calculate its keyauth so we can add it in a special non-standard location
    # for the redirect result
    resp = chall.response(client.key)
    keyauth = resp.key_authorization
    challSrv.add_http01_response("https-redirect", keyauth)

    # Create a HTTP redirect from the challenge's validation path to an HTTPS
    # path with some parameters
    challengePath = "/.well-known/acme-challenge/{0}".format(token)
    redirectPath = "/.well-known/acme-challenge/https-redirect?params=are&important=to&not=lose"
    challSrv.add_http_redirect(
        challengePath,
        "https://{0}{1}".format(d, redirectPath))


    # Also add an A record for the domain pointing to the interface that the
    # HTTPS HTTP-01 challtestsrv is bound.
    challSrv.add_a_record(d, ["10.77.77.77"])

    auth_and_issue([d], client=client, chall_type="http-01")

    challSrv.remove_http_redirect(challengePath)
    challSrv.remove_a_record(d)

    history = challSrv.http_request_history(d)
    challSrv.clear_http_request_history(d)

    # There should have been at least two GET requests made to the challtestsrv by the VA
    if len(history) < 2:
        raise Exception("Expected 2 HTTP request events on challtestsrv, found {0}".format(len(history)))

    initialRequests = []
    redirectedRequests = []

    for request in history:
      # Initial requests should have the expected initial HTTP-01 URL for the challenge
      if request['URL'] == challengePath:
        initialRequests.append(request)
      # Redirected requests should have the expected redirect path URL with all
      # its parameters
      elif request['URL'] == redirectPath:
        redirectedRequests.append(request)
      else:
        raise Exception("Unexpected request URL {0} in challtestsrv history: {1}".format(request['URL'], request))

    # There should have been at least 1 initial HTTP-01 validation request.
    if len(initialRequests) < 1:
        raise Exception("Expected {0} initial HTTP-01 request events on challtestsrv, found {1}".format(validation_attempts, len(initialRequests)))
     # All initial requests should have been over HTTP
    for r in initialRequests:
      if r['HTTPS'] is True:
        raise Exception("Expected all initial requests to be HTTP")

    # There should have been at least 1 redirected HTTP request for each VA
    if len(redirectedRequests) < 1:
        raise Exception("Expected {0} redirected HTTP-01 request events on challtestsrv, found {1}".format(validation_attempts, len(redirectedRequests)))
    # All the redirected requests should have been over HTTPS with the correct
    # SNI value
    for r in redirectedRequests:
      if r['HTTPS'] is False:
        raise Exception("Expected all redirected requests to be HTTPS")
      elif r['ServerName'] != d:
        raise Exception("Expected all redirected requests to have ServerName {0} got \"{1}\"".format(d, r['ServerName']))

class SlowHTTPRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            # Sleeptime needs to be larger than the RA->VA timeout (20s at the
            # time of writing)
            sleeptime = 22
            print("SlowHTTPRequestHandler: sleeping for {0}s\n".format(sleeptime))
            time.sleep(sleeptime)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'this is not an ACME key authorization')
        except:
            pass

def test_http_challenge_timeout():
    """
    test_http_challenge_timeout tests that the VA times out challenge requests
    to a slow HTTP server appropriately.
    """
    # Start a simple python HTTP server on port 5002 in its own thread.
    # NOTE(@cpu): The pebble-challtestsrv binds 10.77.77.77:5002 for HTTP-01
    # challenges so we must use the 10.88.88.88 address for the throw away
    # server for this test and add a mock DNS entry that directs the VA to it.
    httpd = HTTPServer(('10.88.88.88', 5002), SlowHTTPRequestHandler)
    thread = threading.Thread(target = httpd.serve_forever)
    thread.daemon = False
    thread.start()

    # Pick a random domain
    hostname = random_domain()

    # Add A record for the domains to ensure the VA's requests are directed
    # to the interface that we bound the HTTPServer to.
    challSrv.add_a_record(hostname, ["10.88.88.88"])

    start = datetime.datetime.utcnow()
    end = 0

    try:
        # We expect a connection timeout error to occur
        chisel.expect_problem("urn:acme:error:connection",
            lambda: auth_and_issue([hostname], chall_type="http-01"))
        end = datetime.datetime.utcnow()
    finally:
        # Shut down the HTTP server gracefully and join on its thread.
        httpd.shutdown()
        httpd.server_close()
        thread.join()

    delta = end - start
    # Expected duration should be the RA->VA timeout plus some padding (At
    # present the timeout is 20s so adding 2s of padding = 22s)
    expectedDuration = 22
    if delta.total_seconds() == 0 or delta.total_seconds() > expectedDuration:
        raise Exception("expected timeout to occur in under {0} seconds. Took {1}".format(expectedDuration, delta.total_seconds()))

def test_tls_alpn_challenge():
    # Pick two random domains
    domains = [random_domain(), random_domain()]

    # Add A records for these domains to ensure the VA's requests are directed
    # to the interface that the challtestsrv has bound for TLS-ALPN-01 challenge
    # responses
    for host in domains:
        challSrv.add_a_record(host, ["10.88.88.88"])

    auth_and_issue(domains, chall_type="tls-alpn-01")

    for host in domains:
        challSrv.remove_a_record(host)

def test_issuer():
    """
    Issue a certificate, fetch its chain, and verify the chain and
    certificate against test/test-root.pem. Note: This test only handles chains
    of length exactly 1.
    """
    certr, authzs = auth_and_issue([random_domain()])
    cert = urllib2.urlopen(certr.uri).read()
    # In the future the chain URI will use HTTPS so include the root certificate
    # for the WFE's PKI. Note: We use the requests library here so we honor the
    # REQUESTS_CA_BUNDLE passed by test.sh.
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

def test_ocsp():
    cert_file_pem = os.path.join(tempdir, "cert.pem")
    auth_and_issue([random_domain()], cert_output=cert_file_pem)

    ee_ocsp_url = "http://localhost:4002"

    # As OCSP-Updater is generating responses independently of the CA we sit in a loop
    # checking OCSP until we either see a good response or we timeout (5s).
    wait_for_ocsp_good(cert_file_pem, "test/test-ca2.pem", ee_ocsp_url)

def test_ct_submission():
    hostname = random_domain()

    # These should correspond to the configured logs in ra.json.
    log_groups = [
        ["http://boulder:4500/submissions", "http://boulder:4501/submissions"],
        ["http://boulder:4510/submissions", "http://boulder:4511/submissions"],
    ]
    def submissions(group):
        count = 0
        for log in group:
            count += int(urllib2.urlopen(log + "?hostnames=%s" % hostname).read())
        return count

    auth_and_issue([hostname])

    got = [ submissions(log_groups[0]), submissions(log_groups[1]) ]
    expected = [ 1, 2 ]

    for i in range(len(log_groups)):
        if got[i] < expected[i]:
            raise Exception("For log group %d, got %d submissions, expected %d." %
                (i, got[i], expected[i]))

def test_expiration_mailer():
    email_addr = "integration.%x@letsencrypt.org" % random.randrange(2**16)
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
    reset_akamai_purges()
    client.revoke(cert.body, 0)

    cert_file_pem = os.path.join(tempdir, "revokeme.pem")
    with open(cert_file_pem, "w") as f:
        f.write(OpenSSL.crypto.dump_certificate(
            OpenSSL.crypto.FILETYPE_PEM, cert.body.wrapped).decode())
    ee_ocsp_url = "http://localhost:4002"
    verify_revocation(cert_file_pem, "test/test-ca2.pem", ee_ocsp_url)
    verify_akamai_purge()
    return 0

def test_caa():
    """Request issuance for two CAA domains, one where we are permitted and one where we are not.
       Two further sub-domains have restricted validationmethods.
    """
    if len(caa_authzs) == 0:
        raise Exception("CAA authzs not prepared for test_caa")
    for a in caa_authzs:
        response = requests.get(a.uri)
        if response.status_code != 200:
            raise Exception("Unexpected response for CAA authz: ",
                response.status_code)

    # We include a random domain so we don't hit the "exact match" rate limit
    # when testing locally with a persistent database.
    auth_and_issue(["good-caa-reserved.com"])

    # Request issuance for recheck.good-caa-reserved.com, which should
    # now be denied due to CAA.
    chisel.expect_problem("urn:acme:error:caa", lambda: chisel.issue(caa_client, caa_authzs))

    chisel.expect_problem("urn:acme:error:caa",
        lambda: auth_and_issue(["bad-caa-reserved.com"]))

    # TODO(@4a6f656c): Once the `CAAValidationMethods` feature flag is enabled by
    # default, remove this early return.
    if not CONFIG_NEXT:
        return

    chisel.expect_problem("urn:acme:error:caa",
        lambda: auth_and_issue(["dns-01-only.good-caa-reserved.com"], chall_type="http-01"))

    chisel.expect_problem("urn:acme:error:caa",
        lambda: auth_and_issue(["http-01-only.good-caa-reserved.com"], chall_type="dns-01"))

    # Note: the additional names are to avoid rate limiting...
    auth_and_issue(["dns-01-only.good-caa-reserved.com", "www.dns-01-only.good-caa-reserved.com"], chall_type="dns-01")
    auth_and_issue(["http-01-only.good-caa-reserved.com", "www.http-01-only.good-caa-reserved.com"], chall_type="http-01")
    auth_and_issue(["dns-01-or-http-01.good-caa-reserved.com", "dns-01-only.good-caa-reserved.com"], chall_type="dns-01")
    auth_and_issue(["dns-01-or-http-01.good-caa-reserved.com", "http-01-only.good-caa-reserved.com"], chall_type="http-01")

    # CAA should fail with an arbitrary account, but succeed with the caa_client.
    chisel.expect_problem("urn:acme:error:caa", lambda: auth_and_issue(["accounturi.good-caa-reserved.com"]))
    auth_and_issue(["accounturi.good-caa-reserved.com"], client=caa_client)

def test_account_update():
    """
    Create a new ACME client/account with one contact email. Then update the
    account to a different contact emails.
    """
    emails=("initial-email@not-example.com", "updated-email@not-example.com", "another-update@not-example.com")
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
    if not CONFIG_NEXT:
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

def test_admin_revoker_cert():
    cert_file_pem = os.path.join(tempdir, "ar-cert.pem")
    cert, _ = auth_and_issue([random_domain()], cert_output=cert_file_pem)
    serial = "%x" % cert.body.get_serial_number()
    # Revoke certificate by serial
    reset_akamai_purges()
    run("./bin/admin-revoker serial-revoke --config %s/admin-revoker.json %s %d" % (
        default_config_dir, serial, 1))
    # Wait for OCSP response to indicate revocation took place
    ee_ocsp_url = "http://localhost:4002"
    verify_revocation(cert_file_pem, "test/test-ca2.pem", ee_ocsp_url)
    verify_akamai_purge()

def test_admin_revoker_authz():
    # Make an authz, but don't attempt its challenges.
    authz_resource = chisel.make_client().request_domain_challenges("ar-auth-test.com")
    url = authz_resource.uri
    # Revoke authorization by domain
    output = run(
            "./bin/admin-revoker auth-revoke --config %s/admin-revoker.json ar-auth-test.com" % (default_config_dir))
    if "Revoked 1 pending authorizations and 0 final authorizations" not in output:
        raise Exception("admin-revoker didn't revoke the expected number of pending and finalized authorizations")
    # Check authorization has actually been revoked
    response = urllib2.urlopen(url)
    data = json.loads(response.read())
    if data['status'] != "revoked":
        raise Exception("Authorization wasn't revoked")

def test_sct_embedding():
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
