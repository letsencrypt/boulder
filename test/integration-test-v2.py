#!/usr/bin/env python2.7
"""
Integration test for ACMEv2 as implemented by boulder-wfe2.

Currently (December 2017) this depends on the acme-v2-integration branch of
Certbot, while we wait on landing some of our changes in master.
"""
import atexit
import random
import shutil
import subprocess
import tempfile

import startservers

import chisel2
from chisel2 import auth_and_issue, make_client, make_csr, do_dns_challenges, do_http_challenges

from acme.messages import Status

exit_status = 1
tempdir = tempfile.mkdtemp()

def random_domain():
    """Generate a random domain for testing (to avoid rate limiting)."""
    return "rand.%x.xyz" % random.randrange(2**32)

def main():
    if not startservers.start(race_detection=True):
        raise Exception("startservers failed")

    test_multidomain()
    test_wildcardmultidomain()
    test_overlapping_wildcard()
    test_wildcard_exactblacklist()
    test_wildcard_authz_reuse()
    test_order_reuse_failed_authz()

    if not startservers.check():
        raise Exception("startservers.check failed")

    global exit_status
    exit_status = 0

def test_multidomain():
    auth_and_issue([random_domain(), random_domain()])

def test_wildcardmultidomain():
    """
    Test issuance for a random domain and a random wildcard domain using DNS-01.
    """
    auth_and_issue([random_domain(), "*."+random_domain()], chall_type="dns-01")

def test_overlapping_wildcard():
    """
    Test issuance for a random domain and a wildcard version of the same domain
    using DNS-01. This should result in *two* distinct authorizations.
    """
    domain = random_domain()
    domains = [ domain, "*."+domain ]
    client = make_client(None)
    csr_pem = make_csr(domains)
    order = client.new_order(csr_pem)
    authzs = order.authorizations

    if len(authzs) != 2:
        raise Exception("order for %s had %d authorizations, expected 2" %
                (domains, len(authzs)))

    cleanup = do_dns_challenges(client, authzs)
    try:
        order = client.poll_order_and_request_issuance(order)
    finally:
        cleanup()

def test_wildcard_exactblacklist():
    """
    Test issuance for a wildcard that would cover an exact blacklist entry. It
    should fail with a policy error.
    """

    # We include "highrisk.le-test.hoffman-andrews.com" in `test/hostname-policy.json`
    # Issuing for "*.le-test.hoffman-andrews.com" should be blocked
    domain = "*.le-test.hoffman-andrews.com"
    # We expect this to produce a policy problem
    chisel2.expect_problem("urn:ietf:params:acme:error:rejectedIdentifier",
        lambda: auth_and_issue([domain], chall_type="dns-01"))

def test_wildcard_authz_reuse():
    """
    Test that an authorization for a base domain obtained via HTTP-01 isn't
    reused when issuing a wildcard for that base domain later on.
    """

    # Create one client to reuse across multiple issuances
    client = make_client(None)

    # Pick a random domain to issue for
    domains = [ random_domain() ]
    csr_pem = make_csr(domains)

    # Submit an order for the name
    order = client.new_order(csr_pem)
    # Complete the order via an HTTP-01 challenge
    cleanup = do_http_challenges(client, order.authorizations)
    try:
        order = client.poll_order_and_request_issuance(order)
    finally:
        cleanup()

    # Now try to issue a wildcard for the random domain
    domains[0] = "*." + domains[0]
    csr_pem = make_csr(domains)
    order = client.new_order(csr_pem)

    # We expect all of the returned authorizations to be pending status
    for authz in order.authorizations:
        if authz.body.status != Status("pending"):
            raise Exception("order for %s included a non-pending authorization (status: %s) from a previous HTTP-01 order" %
                    ((domains), str(authz.body.status)))

def test_order_reuse_failed_authz():
    """
    Test that creating an order for a domain name, failing an authorization in
    that order, and submitting another new order request for the same name
    doesn't reuse a failed authorizaton in the new order.
    """

    client = make_client(None)
    domains = [ random_domain() ]
    csr_pem = make_csr(domains)

    order = client.new_order(csr_pem)
    firstOrderURI = order.uri

    # Pick the first authz's first challenge, doesn't matter what type it is
    chall_body = order.authorizations[0].body.challenges[0]
    # Answer it, but with nothing set up to solve the challenge request
    client.answer_challenge(chall_body, chall_body.response(client.key))

    # Wait for validation to occur
    # TODO(@cpu): This should be handled better but it involves Python
    # concurrency and I'm going to punt on that while working on other parts of
    # this PR
    import time
    time.sleep(10)

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
    cleanup = do_http_challenges(client, order.authorizations)
    try:
        order = client.poll_order_and_request_issuance(order)
    finally:
        cleanup()

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
