#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-
"""
Integration test cases for ACMEv2 as implemented by boulder-wfe2.
"""
import subprocess
import requests
import datetime
import time
import os
import json

import OpenSSL

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

import chisel2
from helpers import *

from acme import errors as acme_errors

from acme.messages import Status, CertificateRequest, Directory
from acme import crypto_util as acme_crypto_util
from acme import client as acme_client
from acme import messages
from acme import challenges
from acme import errors

import josepy

import tempfile
import shutil
import atexit

import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
import socketserver
import socket

import challtestsrv
challSrv = challtestsrv.ChallTestServer()

def test_multidomain():
    chisel2.auth_and_issue([random_domain(), random_domain()])

def test_wildcardmultidomain():
    """
    Test issuance for a random domain and a random wildcard domain using DNS-01.
    """
    chisel2.auth_and_issue([random_domain(), "*."+random_domain()], chall_type="dns-01")

def test_http_challenge():
    chisel2.auth_and_issue([random_domain(), random_domain()], chall_type="http-01")

def rand_http_chall(client):
    d = random_domain()
    csr_pem = chisel2.make_csr([d])
    order = client.new_order(csr_pem)
    authzs = order.authorizations
    for a in authzs:
        for c in a.body.challenges:
            if isinstance(c.chall, challenges.HTTP01):
                return d, c.chall
    raise Exception("No HTTP-01 challenge found for random domain authz")

def test_http_challenge_broken_redirect():
    """
    test_http_challenge_broken_redirect tests that a common webserver
    mis-configuration receives the correct specialized error message when attempting
    an HTTP-01 challenge.
    """
    client = chisel2.make_client()

    # Create an authz for a random domain and get its HTTP-01 challenge token
    d, chall = rand_http_chall(client)
    token = chall.encode("token")

    # Create a broken HTTP redirect similar to a sort we see frequently "in the wild"
    challengePath = "/.well-known/acme-challenge/{0}".format(token)
    redirect = "http://{0}.well-known/acme-challenge/bad-bad-bad".format(d)
    challSrv.add_http_redirect(
        challengePath,
        redirect)

    # Expect the specialized error message
    expectedError = "Fetching {0}: Invalid host in redirect target \"{1}.well-known\". Check webserver config for missing '/' in redirect target.".format(redirect, d)

    # NOTE(@cpu): Can't use chisel2.expect_problem here because it doesn't let
    # us interrogate the detail message easily.
    try:
        chisel2.auth_and_issue([d], client=client, chall_type="http-01")
    except acme_errors.ValidationError as e:
        for authzr in e.failed_authzrs:
            c = chisel2.get_chall(authzr, challenges.HTTP01)
            error = c.error
            if error is None or error.typ != "urn:ietf:params:acme:error:connection":
                raise Exception("Expected connection prob, got %s" % (error.__str__()))
            if error.detail != expectedError:
                raise Exception("Expected prob detail %s, got %s" % (expectedError, error.detail))

    challSrv.remove_http_redirect(challengePath)

def test_http_challenge_loop_redirect():
    client = chisel2.make_client()

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
    chisel2.expect_problem("urn:ietf:params:acme:error:connection",
        lambda: chisel2.auth_and_issue([d], client=client, chall_type="http-01"))

    challSrv.remove_http_redirect(challengePath)

def test_http_challenge_badport_redirect():
    client = chisel2.make_client()

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
    chisel2.expect_problem("urn:ietf:params:acme:error:connection",
        lambda: chisel2.auth_and_issue([d], client=client, chall_type="http-01"))

    challSrv.remove_http_redirect(challengePath)

def test_http_challenge_badhost_redirect():
    client = chisel2.make_client()

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
    chisel2.expect_problem("urn:ietf:params:acme:error:connection",
        lambda: chisel2.auth_and_issue([d], client=client, chall_type="http-01"))

    challSrv.remove_http_redirect(challengePath)

def test_http_challenge_badproto_redirect():
    client = chisel2.make_client()

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
    # domain name is an IP address.
    chisel2.expect_problem("urn:ietf:params:acme:error:connection",
        lambda: chisel2.auth_and_issue([d], client=client, chall_type="http-01"))

    challSrv.remove_http_redirect(challengePath)

def test_http_challenge_http_redirect():
    client = chisel2.make_client()

    # Create an authz for a random domain and get its HTTP-01 challenge token
    d, chall = rand_http_chall(client)
    token = chall.encode("token")
    # Calculate its keyauth so we can add it in a special non-standard location
    # for the redirect result
    resp = chall.response(client.net.key)
    keyauth = resp.key_authorization
    challSrv.add_http01_response("http-redirect", keyauth)

    # Create a HTTP redirect from the challenge's validation path to some other
    # token path where we have registered the key authorization.
    challengePath = "/.well-known/acme-challenge/{0}".format(token)
    redirectPath = "/.well-known/acme-challenge/http-redirect?params=are&important=to&not=lose"
    challSrv.add_http_redirect(
        challengePath,
        "http://{0}{1}".format(d, redirectPath))

    chisel2.auth_and_issue([d], client=client, chall_type="http-01")

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
    client = chisel2.make_client()

    # Create an authz for a random domain and get its HTTP-01 challenge token
    d, chall = rand_http_chall(client)
    token = chall.encode("token")
    # Calculate its keyauth so we can add it in a special non-standard location
    # for the redirect result
    resp = chall.response(client.net.key)
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

    try:
        chisel2.auth_and_issue([d], client=client, chall_type="http-01")
    except errors.ValidationError as e:
        problems = []
        for authzr in e.failed_authzrs:
            for chall in authzr.body.challenges:
                error = chall.error
                if error:
                    problems.append(error.__str__())
        raise Exception("validation problem: %s" % "; ".join(problems))

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
        raise Exception("Expected all initial requests to be HTTP, got %s" % r)

    # There should have been at least 1 redirected HTTP request for each VA
    if len(redirectedRequests) < 1:
        raise Exception("Expected {0} redirected HTTP-01 request events on challtestsrv, found {1}".format(validation_attempts, len(redirectedRequests)))
    # All the redirected requests should have been over HTTPS with the correct
    # SNI value
    for r in redirectedRequests:
      if r['HTTPS'] is False:
        raise Exception("Expected all redirected requests to be HTTPS")
      # TODO(@cpu): The following ServerName test will fail with config-next
      # until https://github.com/letsencrypt/boulder/issues/3969 is fixed.
      if CONFIG_NEXT:
        return
      elif r['ServerName'] != d:
        raise Exception("Expected all redirected requests to have ServerName {0} got \"{1}\"".format(d, r['ServerName']))

def test_tls_alpn_challenge():
    # Pick two random domains
    domains = [random_domain(),random_domain()]

    # Add A records for these domains to ensure the VA's requests are directed
    # to the interface that the challtestsrv has bound for TLS-ALPN-01 challenge
    # responses
    for host in domains:
        challSrv.add_a_record(host, ["10.88.88.88"])
    chisel2.auth_and_issue(domains, chall_type="tls-alpn-01")

    for host in domains:
        challSrv.remove_a_record(host)

def test_overlapping_wildcard():
    """
    Test issuance for a random domain and a wildcard version of the same domain
    using DNS-01. This should result in *two* distinct authorizations.
    """
    domain = random_domain()
    domains = [ domain, "*."+domain ]
    client = chisel2.make_client(None)
    csr_pem = chisel2.make_csr(domains)
    order = client.new_order(csr_pem)
    authzs = order.authorizations

    if len(authzs) != 2:
        raise Exception("order for %s had %d authorizations, expected 2" %
                (domains, len(authzs)))

    cleanup = chisel2.do_dns_challenges(client, authzs)
    try:
        order = client.poll_and_finalize(order)
    finally:
        cleanup()

def test_highrisk_blocklist():
    """
    Test issuance for a subdomain of a HighRiskBlockedNames entry. It should
    fail with a policy error.
    """

    # We include "example.org" in `test/hostname-policy.yaml` in the
    # HighRiskBlockedNames list so issuing for "foo.example.org" should be
    # blocked.
    domain = "foo.example.org"
    # We expect this to produce a policy problem
    chisel2.expect_problem("urn:ietf:params:acme:error:rejectedIdentifier",
        lambda: chisel2.auth_and_issue([domain], chall_type="dns-01"))

def test_wildcard_exactblacklist():
    """
    Test issuance for a wildcard that would cover an exact blacklist entry. It
    should fail with a policy error.
    """

    # We include "highrisk.le-test.hoffman-andrews.com" in `test/hostname-policy.yaml`
    # Issuing for "*.le-test.hoffman-andrews.com" should be blocked
    domain = "*.le-test.hoffman-andrews.com"
    # We expect this to produce a policy problem
    chisel2.expect_problem("urn:ietf:params:acme:error:rejectedIdentifier",
        lambda: chisel2.auth_and_issue([domain], chall_type="dns-01"))

def test_wildcard_authz_reuse():
    """
    Test that an authorization for a base domain obtained via HTTP-01 isn't
    reused when issuing a wildcard for that base domain later on.
    """

    # Create one client to reuse across multiple issuances
    client = chisel2.make_client(None)

    # Pick a random domain to issue for
    domains = [ random_domain() ]
    csr_pem = chisel2.make_csr(domains)

    # Submit an order for the name
    order = client.new_order(csr_pem)
    # Complete the order via an HTTP-01 challenge
    cleanup = chisel2.do_http_challenges(client, order.authorizations)
    try:
        order = client.poll_and_finalize(order)
    finally:
        cleanup()

    # Now try to issue a wildcard for the random domain
    domains[0] = "*." + domains[0]
    csr_pem = chisel2.make_csr(domains)
    order = client.new_order(csr_pem)

    # We expect all of the returned authorizations to be pending status
    for authz in order.authorizations:
        if authz.body.status != Status("pending"):
            raise Exception("order for %s included a non-pending authorization (status: %s) from a previous HTTP-01 order" %
                    ((domains), str(authz.body.status)))

def test_bad_overlap_wildcard():
    chisel2.expect_problem("urn:ietf:params:acme:error:malformed",
        lambda: chisel2.auth_and_issue(["*.example.com", "www.example.com"]))

def test_duplicate_orders():
    """
    Test that the same client issuing for the same domain names twice in a row
    works without error.
    """
    client = chisel2.make_client(None)
    domains = [ random_domain() ]
    chisel2.auth_and_issue(domains, client=client)
    chisel2.auth_and_issue(domains, client=client)

def test_order_reuse_failed_authz():
    """
    Test that creating an order for a domain name, failing an authorization in
    that order, and submitting another new order request for the same name
    doesn't reuse a failed authorizaton in the new order.
    """

    client = chisel2.make_client(None)
    domains = [ random_domain() ]
    csr_pem = chisel2.make_csr(domains)

    order = client.new_order(csr_pem)
    firstOrderURI = order.uri

    # Pick the first authz's first challenge, doesn't matter what type it is
    chall_body = order.authorizations[0].body.challenges[0]
    # Answer it, but with nothing set up to solve the challenge request
    client.answer_challenge(chall_body, chall_body.response(client.net.key))

    deadline = datetime.datetime.now() + datetime.timedelta(seconds=60)
    authzFailed = False
    try:
        # Poll the order's authorizations until they are non-pending, a timeout
        # occurs, or there is an invalid authorization status.
        client.poll_authorizations(order, deadline)
    except acme_errors.ValidationError as e:
        # We expect there to be a ValidationError from one of the authorizations
        # being invalid.
        authzFailed = True

    # If the poll ended and an authz's status isn't invalid then we reached the
    # deadline, fail the test
    if not authzFailed:
        raise Exception("timed out waiting for order %s to become invalid" % firstOrderURI)

    # Make another order with the same domains
    order = client.new_order(csr_pem)

    # It should not be the same order as before
    if order.uri == firstOrderURI:
        raise Exception("new-order for %s returned a , now-invalid, order" % domains)

    # We expect all of the returned authorizations to be pending status
    for authz in order.authorizations:
        if authz.body.status != Status("pending"):
            raise Exception("order for %s included a non-pending authorization (status: %s) from a previous order" %
                    ((domains), str(authz.body.status)))

    # We expect the new order can be fulfilled
    cleanup = chisel2.do_http_challenges(client, order.authorizations)
    try:
        order = client.poll_and_finalize(order)
    finally:
        cleanup()

def test_order_finalize_early():
    """
    Test that finalizing an order before its fully authorized results in the
    order having an error set and the status being invalid.
    """
    # Create a client
    client = chisel2.make_client(None)

    # Create a random domain and a csr
    domains = [ random_domain() ]
    csr_pem = chisel2.make_csr(domains)

    # Create an order for the domain
    order = client.new_order(csr_pem)

    deadline = datetime.datetime.now() + datetime.timedelta(seconds=5)

    # Finalizing an order early should generate an orderNotReady error.
    chisel2.expect_problem("urn:ietf:params:acme:error:orderNotReady",
        lambda: client.finalize_order(order, deadline))

def test_revoke_by_issuer():
    client = chisel2.make_client(None)
    order = chisel2.auth_and_issue([random_domain()], client=client)

    cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, order.fullchain_pem)
    reset_akamai_purges()
    client.revoke(josepy.ComparableX509(cert), 0)

    cert_file_pem = os.path.join(tempdir, "revokeme.pem")
    with open(cert_file_pem, "w") as f:
        f.write(OpenSSL.crypto.dump_certificate(
            OpenSSL.crypto.FILETYPE_PEM, cert).decode())
    ee_ocsp_url = "http://localhost:4002"
    verify_revocation(cert_file_pem, "test/test-ca2.pem", ee_ocsp_url)
    verify_akamai_purge()

def test_revoke_by_authz():
    domains = [random_domain()]
    order = chisel2.auth_and_issue(domains)

    # create a new client and re-authz
    client = chisel2.make_client(None)
    chisel2.auth_and_issue(domains, client=client)

    cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, order.fullchain_pem)
    reset_akamai_purges()
    client.revoke(josepy.ComparableX509(cert), 0)

    cert_file_pem = os.path.join(tempdir, "revokeme.pem")
    with open(cert_file_pem, "w") as f:
        f.write(OpenSSL.crypto.dump_certificate(
            OpenSSL.crypto.FILETYPE_PEM, cert).decode())
    ee_ocsp_url = "http://localhost:4002"
    verify_revocation(cert_file_pem, "test/test-ca2.pem", ee_ocsp_url)
    verify_akamai_purge()

def test_revoke_by_privkey():
    client = chisel2.make_client(None)
    domains = [random_domain()]
    key = OpenSSL.crypto.PKey()
    key.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)
    key_pem = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, key)
    csr_pem = chisel2.make_csr(domains)
    order = client.new_order(csr_pem)
    cleanup = chisel2.do_http_challenges(client, order.authorizations)
    try:
        order = client.poll_and_finalize(order)
    finally:
        cleanup()

    # Create a new client with the JWK as the cert private key
    jwk = josepy.JWKRSA(key=key)
    net = acme_client.ClientNetwork(key, user_agent="Boulder integration tester")

    directory = Directory.from_json(net.get(chisel2.DIRECTORY_V2).json())
    new_client = acme_client.ClientV2(directory, net)

    cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, order.fullchain_pem)
    reset_akamai_purges()
    client.revoke(josepy.ComparableX509(cert), 0)

    cert_file_pem = os.path.join(tempdir, "revokeme.pem")
    with open(cert_file_pem, "w") as f:
        f.write(OpenSSL.crypto.dump_certificate(
            OpenSSL.crypto.FILETYPE_PEM, cert).decode())
    ee_ocsp_url = "http://localhost:4002"
    verify_revocation(cert_file_pem, "test/test-ca2.pem", ee_ocsp_url)
    verify_akamai_purge()

def test_sct_embedding():
    order = chisel2.auth_and_issue([random_domain()])
    cert = x509.load_pem_x509_certificate(str(order.fullchain_pem), default_backend())

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

def test_only_return_existing_reg():
    client = chisel2.uninitialized_client()
    email = "test@not-example.com"
    client.new_account(messages.NewRegistration.from_data(email=email,
            terms_of_service_agreed=True))
    
    client = chisel2.uninitialized_client(key=client.net.key)
    class extendedAcct(dict):
        def json_dumps(self, indent=None):
            return json.dumps(self)
    acct = extendedAcct({
        "termsOfServiceAgreed": True,
        "contact": [email],
        "onlyReturnExisting": True
    })
    resp = client.net.post(client.directory['newAccount'], acct, acme_version=2)
    if resp.status_code != 200:
        raise Exception("incorrect response returned for onlyReturnExisting")

    other_client = chisel2.uninitialized_client()
    newAcct = extendedAcct({
        "termsOfServiceAgreed": True,
        "contact": [email],
        "onlyReturnExisting": True
    })
    chisel2.expect_problem("urn:ietf:params:acme:error:accountDoesNotExist",
        lambda: other_client.net.post(other_client.directory['newAccount'], newAcct, acme_version=2))

def BouncerHTTPRequestHandler(redirect, guestlist):
    """
    BouncerHTTPRequestHandler returns a BouncerHandler class that acts like
    a club bouncer in front of another server. The bouncer will respond to
    GET requests by looking up the allowed number of requests in the guestlist
    for the User-Agent making the request. If there is at least one guestlist
    spot for that UA it will be redirected to the real server and the
    guestlist will be decremented. Once the guestlist spots for a UA are
    expended requests will get a bogus result and have to stand outside in the
    cold 
    """
    class BouncerHandler(BaseHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            BaseHTTPRequestHandler.__init__(self, *args, **kwargs)

        def do_HEAD(self):
            # This is used by wait_for_server
            self.send_response(200)
            self.end_headers()

        def do_GET(self):
            ua = self.headers['User-Agent']
            guestlistAllows = BouncerHandler.guestlist.get(ua, 0)
            # If there is still space on the guestlist for this UA then redirect
            # the request and decrement the guestlist.
            if guestlistAllows > 0:
                BouncerHandler.guestlist[ua] -= 1
                self.log_message("BouncerHandler UA {0} is on the Guestlist. {1} requests remaining.".format(ua, BouncerHandler.guestlist[ua]))
                self.send_response(302)
                self.send_header("Location", BouncerHandler.redirect)
                self.end_headers()
            # Otherwise return a bogus result
            else:
                self.log_message("BouncerHandler UA {0} has no requests on the Guestlist. Sending request to the curb".format(ua))
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'(• ◡ •) <( VIPs only! )')

    BouncerHandler.guestlist = guestlist
    BouncerHandler.redirect = redirect
    return BouncerHandler

def wait_for_server(addr):
    while True:
        try:
            # NOTE(@cpu): Using HEAD here instead of GET because the
            # BouncerHandler modifies its state for GET requests.
            status = requests.head(addr).status_code
            if status == 200:
                return
        except requests.exceptions.ConnectionError:
            pass
        time.sleep(0.5)

def multiva_setup(client, guestlist):
    """
    Create a testing hostname and the multiva server setup. This will block
    until the server is ready. The returned cleanup function should be used to
    stop the server. The first bounceFirst requests to the server will be sent
    to the real challtestsrv for a good answer, the rest will get a bad
    answer.
    """

    hostname = random_domain()
    csr_pem = chisel2.make_csr([hostname])
    order = client.new_order(csr_pem)
    authz = order.authorizations[0]
    chall = None
    for c in authz.body.challenges:
        if isinstance(c.chall, challenges.HTTP01):
            chall = c.chall
    if chall is None:
        raise Exception("No HTTP-01 challenge found for random domain authz")

    token = chall.encode("token")

    # Calculate the challenge's keyauth so we can add a good keyauth response on
    # the real challtestsrv that we redirect VIP requests to.
    resp = chall.response(client.net.key)
    keyauth = resp.key_authorization
    challSrv.add_http01_response(token, keyauth)

    # Add an A record for the domains to ensure the VA's requests are directed
    # to the interface that we bound the HTTPServer to.
    challSrv.add_a_record(hostname, ["10.88.88.88"])

    # Add an A record for the redirect target that sends it to the real chall
    # test srv for a valid HTTP-01 response.
    redirHostname = "pebble-challtestsrv.example.com"
    challSrv.add_a_record(redirHostname, ["10.77.77.77"])

    # Start a simple python HTTP server on port 5002 in its own thread.
    # NOTE(@cpu): The pebble-challtestsrv binds 10.77.77.77:5002 for HTTP-01
    # challenges so we must use the 10.88.88.88 address for the throw away
    # server for this test and add a mock DNS entry that directs the VA to it.
    redirect = "http://{0}/.well-known/acme-challenge/{1}".format(
            redirHostname, token)
    httpd = HTTPServer(('10.88.88.88', 5002), BouncerHTTPRequestHandler(redirect, guestlist))
    thread = threading.Thread(target = httpd.serve_forever)
    thread.daemon = False
    thread.start()

    def cleanup():
        # Remove the challtestsrv mocks
        challSrv.remove_a_record(hostname)
        challSrv.remove_a_record(redirHostname)
        challSrv.remove_http01_response(token)
        # Shut down the HTTP server gracefully and join on its thread.
        httpd.shutdown()
        httpd.server_close()
        thread.join()

    return hostname, cleanup

def test_http_multiva_threshold_pass():
    # Only config-next has remote VAs configured and is appropriate for this
    # integration test.
    if not CONFIG_NEXT:
        return

    client = chisel2.make_client()

    # Configure a guestlist that will pass the multiVA threshold test by
    # allowing the primary VA and one remote.
    guestlist = {"boulder": 1, "boulder-remote-b": 1}

    hostname, cleanup = multiva_setup(client, guestlist)

    try:
        # With the maximum number of allowed remote VA failures the overall
        # challenge should still succeed.
        chisel2.auth_and_issue([hostname], client=client, chall_type="http-01")
    finally:
        cleanup()

def test_http_multiva_threshold_fail():
    # Only config-next has remote VAs configured and is appropriate for this
    # integration test.
    if not CONFIG_NEXT:
        return

    client = chisel2.make_client()

    # Configure a guestlist that will fail the multiVA threshold test by
    # only allowing the primary VA.
    guestlist = {"boulder": 1}

    hostname, cleanup = multiva_setup(client, guestlist)

    try:
        chisel2.auth_and_issue([hostname], client=client, chall_type="http-01")
    except acme_errors.ValidationError as e:
        # NOTE(@cpu): Chisel2's expect_problem doesn't work in this case so this
        # test needs to unpack an `acme_errors.ValidationError` on its own. It
        # might be possible to clean this up in the future.
        if len(e.failed_authzrs) != 1:
            raise Exception("expected one failed authz, found {0}".format(len(e.failed_authzrs)))
        challs = e.failed_authzrs[0].body.challenges
        httpChall = None
        for chall_body in challs:
            if isinstance(chall_body.chall, challenges.HTTP01):
                httpChall = chall_body
        if httpChall is None:
            raise Exception("no HTTP-01 challenge in failed authz")
        if httpChall.error.typ != "urn:ietf:params:acme:error:unauthorized":
            raise Exception("expected unauthorized prob, found {0}".format(httpChall.error.typ))
    finally:
        cleanup()

class FakeH2ServerHandler(socketserver.BaseRequestHandler):
    """
    FakeH2ServerHandler is a TCP socket handler that writes data representing an
    initial HTTP/2 SETTINGS frame as a response to all received data.
    """
    def handle(self):
        # Read whatever the HTTP request was so that the response isn't seen as
        # unsolicited.
        self.data = self.request.recv(1024).strip()
        # Blast some HTTP/2 bytes onto the socket
        # Truncated example data from taken from the community forum:
        # https://community.letsencrypt.org/t/le-validation-error-if-server-is-in-google-infrastructure/51841
        self.request.sendall(b'\x00\x00\x12\x04\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x80\x00')

def wait_for_tcp_server(addr, port):
    """
    wait_for_tcp_server attempts to make a TCP connection to the given
    address/port every 0.5s until it succeeds.
    """
    while True:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect((addr, port))
            sock.sendall("\n")
            return
        except socket.error:
            time.sleep(0.5)
            pass

def test_http2_http01_challenge():
    """
    test_http2_http01_challenge tests that an HTTP-01 challenge made to a HTTP/2
    server fails with a specific error message for this case.
    """
    client = chisel2.make_client()
    hostname = "fake.h2.example.com"

    # Add an A record for the test server to ensure the VA's requests are directed
    # to the interface that we bind the FakeH2ServerHandler to.
    challSrv.add_a_record(hostname, ["10.88.88.88"])

    # Allow socket address reuse on the base TCPServer class. Failing to do this
    # causes subsequent integration tests to fail with "Address in use" errors even
    # though this test _does_ call shutdown() and server_close(). Even though the
    # server was shut-down Python's socket will be in TIME_WAIT because of prev. client
    # connections. Having the TCPServer set SO_REUSEADDR on the socket solves
    # the problem.
    socketserver.TCPServer.allow_reuse_address = True
    # Create, start, and wait for a fake HTTP/2 server.
    server = socketserver.TCPServer(('10.88.88.88', 5002), FakeH2ServerHandler)
    thread = threading.Thread(target = server.serve_forever)
    thread.daemon = False
    thread.start()
    wait_for_tcp_server('10.88.88.88', 5002)

    # Issuing an HTTP-01 challenge for this hostname should produce a connection
    # problem with an error specific to the HTTP/2 misconfiguration.
    expectedError = "Server is speaking HTTP/2 over HTTP"
    try:
        chisel2.auth_and_issue([hostname], client=client, chall_type="http-01")
    except acme_errors.ValidationError as e:
        for authzr in e.failed_authzrs:
            c = chisel2.get_chall(authzr, challenges.HTTP01)
            error = c.error
            if error is None or error.typ != "urn:ietf:params:acme:error:connection":
                raise Exception("Expected connection prob, got %s" % (error.__str__()))
            if not error.detail.endswith(expectedError):
                raise Exception("Expected prob detail ending in %s, got %s" % (expectedError, error.detail))
    finally:
        server.shutdown()
        server.server_close()
        thread.join()

z1 = type('', (), {})()
z1.reuse_client = None
z1.reuse_authzs = []
@register_twenty_days_ago
def z1_reuse_setup():
    """Runs during "setup_twenty_days_ago" phase."""
    z1.reuse_client = chisel2.make_client()
    order = chisel2.auth_and_issue([random_domain()], client=z1.reuse_client)
    for a in order.authorizations:
        z1.reuse_authzs.append(a)

def test_z1_reuse():
    reuse_domains = []
    authz_uris = set()
    for a in z1.reuse_authzs:
        authz_uris.add(a.uri)
        reuse_domains.append(a.body.identifier.value)
    order = chisel2.auth_and_issue(reuse_domains, client=z1.reuse_client)
    for a in order.authorizations:
        try:
            authz_uris.remove(a.uri)
        except KeyError as e:
            raise Exception("Expected to reuse authzs %s, but got %s" % (authz_uris, a.uri))
    if len(authz_uris) != 0:
        raise Exception("Failed to reuse all authzs")

authz2_reuse_client = None
authz2_reuse_authzs = []
@register_twenty_days_ago
def authz2_reuse_setup():
    """Runs during "setup_twenty_days_ago" phase."""
    authz2_reuse_client = chisel2.make_client()
    old_authz_domains = [random_domain(), random_domain()]
    order = chisel2.auth_and_issue(old_authz_domains, client=authz2_reuse_client)
    for a in order.authorizations:
        authz2_reuse_authzs.append(a)

def test_authz2_reuse():
    reuse_domains = []
    authz_uris = set()
    for a in authz2_reuse_authzs:
        authz_uris.add(a.uri)
        reuse_domains.append(a.body.identifier.value)
    print("AITHZZ2 REUSE", reuse_domains)
    order = chisel2.auth_and_issue(reuse_domains, client=authz2_reuse_client)
    for a in order.authorizations:
        try:
            authz_uris.remove(a.uri)
        except KeyError as e:
            raise Exception("Expected to reuse authzs %s, but got %s" % (authz_uris, a.uri))
    if len(authz_uris) != 0:
        raise Exception("Failed to reuse all authzs")

def test_new_order_policy_errs():
    """
    Test that creating an order with policy blocked identifiers returns
    a problem with subproblems.
    """
    client = chisel2.make_client(None)

    # 'in-addr.arpa' is present in `test/hostname-policy.yaml`'s
    # HighRiskBlockedNames list. 
    csr_pem = chisel2.make_csr(["out-addr.in-addr.arpa", "between-addr.in-addr.arpa"])

    # With two policy blocked names in the order we expect to get back a top
    # level rejectedIdentifier with a detail message that references
    # subproblems.
    #
    # TODO(@cpu): After https://github.com/certbot/certbot/issues/7046 is
    # implemented in the upstream `acme` module this test should also ensure the
    # subproblems are properly represented.
    ok = False
    try:
        order = client.new_order(csr_pem)
    except messages.Error as e:
        ok = True
        if e.typ != "urn:ietf:params:acme:error:rejectedIdentifier":
            raise Exception('Expected rejectedIdentifier type problem, got {0}'.format(e.typ))
        if e.detail != 'Error creating new order :: Policy forbids issuing for "out-addr.in-addr.arpa" and 1 more identifiers. Refer to sub-problems for more information':
            raise Exception('Order problem detail did not match expected')
    if not ok:
        raise Exception('Expected problem, got no error')

def run(cmd, **kwargs):
    return subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, **kwargs)
