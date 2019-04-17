#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-
"""
This file contains basic infrastructure for running the integration test cases.
Most test cases are in v1_integration.py and v2_integration.py. There are a few
exceptions: Test cases that don't test either the v1 or v2 API are in this file,
and test cases that have to run at a specific point in the cycle (e.g. after all
other test cases) are also in this file.
"""
import argparse
import atexit
import datetime
import inspect
import json
import os
import random
import re
import requests
import subprocess
import signal

import startservers

import chisel
from chisel import auth_and_issue
import v1_integration
import v2_integration
from helpers import *

from acme import challenges

import requests

import challtestsrv
challSrv = challtestsrv.ChallTestServer()

def setup_seventy_days_ago():
    """Do any setup that needs to happen 70 days in the past, for tests that
       will run in the 'present'.
    """
    # Issue a certificate with the clock set back, and save the authzs to check
    # later that they are expired (404).
    _, v1_integration.old_authzs = auth_and_issue([random_domain()])

def setup_twenty_days_ago():
    """Do any setup that needs to happen 20 day in the past, for tests that
       will run in the 'present'.
    """
    # Issue a certificate with the clock set back, and save the authzs to check
    # later that they are valid (200). They should however require rechecking for
    # CAA purposes.
    _, v1_integration.caa_authzs = auth_and_issue(["recheck.good-caa-reserved.com"], client=v1_integration.caa_client)

def setup_zero_days_ago():
    """Do any setup that needs to happen at the start of a test run."""
    # Issue a certificate and save the authzs to check that they still exist
    # at a later point.
    _, v1_integration.new_authzs = auth_and_issue([random_domain()])

def run_client_tests():
    root = os.environ.get("CERTBOT_PATH")
    assert root is not None, (
        "Please set CERTBOT_PATH env variable to point at "
        "initialized (virtualenv) client repo root")
    cmd = os.path.join(root, 'tests', 'boulder-integration.sh')
    run(cmd, cwd=root)

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

def test_single_ocsp():
    """Run the single-ocsp command, which is used to generate OCSP responses for
       intermediate certificates on a manual basis. Then start up an
       ocsp-responder configured to respond using the output of single-ocsp,
       check that it successfully answers OCSP requests, and shut the responder
       back down.

       This is a non-API test.
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

def test_stats():
    """Fetch Prometheus metrics from a sample of Boulder components to check
       they are present.

       This is a non-API test.
    """
    def expect_stat(port, stat):
        url = "http://localhost:%d/metrics" % port
        response = requests.get(url)
        if not stat in response.content:
            print(response.content)
            raise Exception("%s not present in %s" % (stat, url))
    expect_stat(8000, "\nresponse_time_count{")
    expect_stat(8000, "\ngo_goroutines ")
    expect_stat(8000, '\ngrpc_client_handling_seconds_count{grpc_method="NewRegistration",grpc_service="ra.RegistrationAuthority",grpc_type="unary"} ')

    expect_stat(8002, '\ngrpc_server_handling_seconds_sum{grpc_method="PerformValidation",grpc_service="ra.RegistrationAuthority",grpc_type="unary"} ')

    expect_stat(8001, "\ngo_goroutines ")

def setup_mock_dns(caa_account_uri=None):
    """
    setup_mock_dns adds mock DNS entries to the running pebble-challtestsrv.
    Integration tests depend on this mock data.
    """

    if caa_account_uri is None:
      caa_account_uri = os.environ.get("ACCOUNT_URI")

    goodCAA = "happy-hacker-ca.invalid"
    badCAA = "sad-hacker-ca.invalid"

    caa_records = [
        {"domain": "bad-caa-reserved.com", "value": badCAA},
        {"domain": "good-caa-reserved.com", "value": goodCAA},
        {"domain": "accounturi.good-caa-reserved.com", "value":"{0}; accounturi={1}".format(goodCAA, caa_account_uri)},
        {"domain": "recheck.good-caa-reserved.com", "value":badCAA},
        {"domain": "dns-01-only.good-caa-reserved.com", "value": "{0}; validationmethods=dns-01".format(goodCAA)},
        {"domain": "http-01-only.good-caa-reserved.com", "value": "{0}; validationmethods=http-01".format(goodCAA)},
        {"domain": "dns-01-or-http01.good-caa-reserved.com", "value": "{0}; validationmethods=dns-01,http-01".format(goodCAA)},
    ]
    for policy in caa_records:
        challSrv.add_caa_issue(policy["domain"], policy["value"])

exit_status = 1

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
    parser.add_argument('--skip-setup', dest="skip_setup", action="store_true",
                        help="skip integration test setup")
    # allow any ACME client to run custom command for integration
    # testing (without having to implement its own busy-wait loop)
    parser.add_argument('--custom', metavar="CMD", help="run custom command")
    parser.set_defaults(run_all=False, run_certbot=False, run_chisel=False,
        run_loadtest=False, test_case_filter="", skip_setup=False)
    args = parser.parse_args()

    if not (args.run_all or args.run_certbot or args.run_chisel or args.run_loadtest or args.custom is not None):
        raise Exception("must run at least one of the letsencrypt or chisel tests with --all, --certbot, --chisel, --load or --custom")

    if not args.skip_setup:
        now = datetime.datetime.utcnow()
        seventy_days_ago = now+datetime.timedelta(days=-70)
        if not startservers.start(race_detection=True, fakeclock=fakeclock(seventy_days_ago)):
            raise Exception("startservers failed (mocking seventy days ago)")
        setup_seventy_days_ago()
        v1_integration.caa_client = caa_client = chisel.make_client()
        startservers.stop()

        now = datetime.datetime.utcnow()
        twenty_days_ago = now+datetime.timedelta(days=-20)
        if not startservers.start(race_detection=True, fakeclock=fakeclock(twenty_days_ago)):
            raise Exception("startservers failed (mocking twenty days ago)")
        setup_twenty_days_ago()
        startservers.stop()

    caa_account_uri = caa_client.account.uri if caa_client is not None else None
    if not startservers.start(race_detection=True, account_uri=caa_account_uri):
        raise Exception("startservers failed")

    if not args.skip_setup:
        setup_zero_days_ago()

    setup_mock_dns(caa_account_uri)

    if args.run_all or args.run_chisel:
        run_chisel(args.test_case_filter)

    if args.run_all or args.run_certbot:
        run_client_tests()

    if args.custom:
        run(args.custom)

    run_cert_checker()
    # Skip load-balancing check when test case filter is on, since that usually
    # means there's a single issuance and we don't expect every RPC backend to get
    # traffic.
    if not args.test_case_filter:
        check_balance()
    run_expired_authz_purger()

    # Run the load-generator last. run_loadtest will stop the
    # pebble-challtestsrv before running the load-generator and will not restart
    # it.
    if args.run_all or args.run_loadtest:
        run_loadtest()

    if not startservers.check():
        raise Exception("startservers.check failed")

    global exit_status
    exit_status = 0

def run_chisel(test_case_filter):
    for key, value in inspect.getmembers(v1_integration):
      if callable(value) and key.startswith('test_') and re.search(test_case_filter, key):
        value()
    for key, value in inspect.getmembers(v2_integration):
      if callable(value) and key.startswith('test_') and re.search(test_case_filter, key):
        value()
    for key, value in globals().items():
      if callable(value) and key.startswith('test_') and re.search(test_case_filter, key):
        value()

def run_loadtest():
    """Run the ACME v2 load generator."""
    latency_data_file = "%s/integration-test-latency.json" % tempdir

    # Stop the global pebble-challtestsrv - it will conflict with the
    # load-generator's internal challtestsrv. We don't restart it because
    # run_loadtest() is called last and there are no remaining tests to run that
    # might benefit from the pebble-challtestsrv being restarted.
    startservers.stopChallSrv()

    run("./bin/load-generator \
            -config test/load-generator/config/integration-test-config.json\
            -results %s" % latency_data_file)

def check_balance():
    """Verify that gRPC load balancing across backends is working correctly.

    Fetch metrics from each backend and ensure the grpc_server_handled_total
    metric is present, which means that backend handled at least one request.
    """
    addresses = [
        "sa1.boulder:8003",
        "sa2.boulder:8103",
        "publisher1.boulder:8009",
        "publisher2.boulder:8109",
        "va1.boulder:8004",
        "va2.boulder:8104",
        "ca1.boulder:8001",
        "ca2.boulder:8104",
        "ra1.boulder:8002",
        "ra2.boulder:8102",
    ]
    for address in addresses:
        metrics = requests.get("http://%s/metrics" % address)
        if not "grpc_server_handled_total" in metrics.text:
            raise Exception("no gRPC traffic processed by %s; load balancing problem?"
                % address)

def run_cert_checker():
    run("./bin/cert-checker -config %s/cert-checker.json" % default_config_dir)

if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as e:
        raise Exception("%s. Output:\n%s" % (e, e.output))

@atexit.register
def stop():
    if exit_status == 0:
        print("\n\nSUCCESS")
    else:
        print("\n\nFAILURE")
