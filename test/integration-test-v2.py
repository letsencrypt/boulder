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
from chisel2 import auth_and_issue, make_client, make_csr, do_dns_challenges

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
                (domains, len(authzs))

    cleanup = do_dns_challenges(client, authzs)
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
