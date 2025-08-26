#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
This file contains basic infrastructure for running the integration test cases.
Most test cases are in v2_integration.py. There are a few exceptions: Test cases
that don't test either the v1 or v2 API are in this file, and test cases that
have to run at a specific point in the cycle (e.g. after all other test cases)
are also in this file.
"""
import argparse
import datetime
import inspect
import os
import re
import subprocess

import requests
import startservers
import v2_integration
from helpers import *

# Set the environment variable RACE to anything other than 'true' to disable
# race detection. This significantly speeds up integration testing cycles
# locally.
race_detection = True
if os.environ.get('RACE', 'true') != 'true':
    race_detection = False

def run_go_tests(filterPattern=None,verbose=False):
    """
    run_go_tests launches the Go integration tests. The go test command must
    return zero or an exception will be raised. If the filterPattern is provided
    it is used as the value of the `--test.run` argument to the go test command.
    """
    cmdLine = ["go", "test"]
    if filterPattern is not None and filterPattern != "":
        cmdLine = cmdLine + ["--test.run", filterPattern]
    cmdLine = cmdLine + ["-tags", "integration", "-count=1", "-race"]
    if verbose:
        cmdLine = cmdLine + ["-v"]
    cmdLine = cmdLine +  ["./test/integration"]
    subprocess.check_call(cmdLine, stderr=subprocess.STDOUT)

exit_status = 1

def main():
    parser = argparse.ArgumentParser(description='Run integration tests')
    parser.add_argument('--chisel', dest="run_chisel", action="store_true",
                        help="run integration tests using chisel")
    parser.add_argument('--coverage', dest="coverage", action="store_true",
                        help="run integration tests with coverage")
    parser.add_argument('--coverage-dir', dest="coverage_dir", action="store",
                        default=f"test/coverage/{datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}",
                        help="directory to store coverage data")
    parser.add_argument('--gotest', dest="run_go", action="store_true",
                        help="run Go integration tests")
    parser.add_argument('--gotestverbose', dest="run_go_verbose", action="store_true",
                        help="run Go integration tests with verbose output")
    parser.add_argument('--filter', dest="test_case_filter", action="store",
                        help="Regex filter for test cases")
    # allow any ACME client to run custom command for integration
    # testing (without having to implement its own busy-wait loop)
    parser.add_argument('--custom', metavar="CMD", help="run custom command")
    parser.set_defaults(run_chisel=False, test_case_filter="", skip_setup=False, coverage=False, coverage_dir=None)
    args = parser.parse_args()

    if args.coverage and args.coverage_dir:
        if not os.path.exists(args.coverage_dir):
            os.makedirs(args.coverage_dir)
        if not os.path.isdir(args.coverage_dir):
            raise(Exception("coverage-dir must be a directory"))

    if not (args.run_chisel or args.custom  or args.run_go is not None):
        raise(Exception("must run at least one of the letsencrypt or chisel tests with --chisel, --gotest, or --custom"))

    if not startservers.install(race_detection=race_detection, coverage=args.coverage):
        raise(Exception("failed to build"))

    if not startservers.start(coverage_dir=args.coverage_dir):
        raise(Exception("startservers failed"))

    if args.run_chisel:
        run_chisel(args.test_case_filter)

    if args.run_go:
        run_go_tests(args.test_case_filter, False)

    if args.run_go_verbose:
        run_go_tests(args.test_case_filter, True)

    if args.custom:
        run(args.custom.split())

    # Skip the last-phase checks when the test case filter is one, because that
    # means we want to quickly iterate on a single test case.
    if not args.test_case_filter:
        run_cert_checker()
        check_balance()

    # If coverage is enabled, process the coverage data
    if args.coverage:
        process_covdata(args.coverage_dir)

    if not startservers.check():
        raise(Exception("startservers.check failed"))

    global exit_status
    exit_status = 0

def run_chisel(test_case_filter):
    for key, value in inspect.getmembers(v2_integration):
      if callable(value) and key.startswith('test_') and re.search(test_case_filter, key):
        value()
    for key, value in globals().items():
      if callable(value) and key.startswith('test_') and re.search(test_case_filter, key):
        value()

def check_balance():
    """Verify that gRPC load balancing across backends is working correctly.

    Fetch metrics from each backend and ensure the grpc_server_handled_total
    metric is present, which means that backend handled at least one request.
    """
    addresses = [
        "localhost:8003", # SA
        "localhost:8103", # SA
        "localhost:8009", # publisher
        "localhost:8109", # publisher
        "localhost:8004", # VA
        "localhost:8104", # VA
        "localhost:8001", # CA
        "localhost:8101", # CA
        "localhost:8002", # RA
        "localhost:8102", # RA
    ]
    for address in addresses:
        metrics = requests.get("http://%s/metrics" % address)
        if "grpc_server_handled_total" not in metrics.text:
            raise(Exception("no gRPC traffic processed by %s; load balancing problem?")
                % address)

def run_cert_checker():
    run(["./bin/boulder", "cert-checker", "-config", "%s/cert-checker.json" % config_dir])

def process_covdata(coverage_dir):
    """Process coverage data and generate reports."""
    if not os.path.exists(coverage_dir):
        raise(Exception("Coverage directory does not exist: %s" % coverage_dir))

    # Generate text report
    coverage_dir = os.path.abspath(coverage_dir)
    cov_text = os.path.join(coverage_dir, "integration.coverprofile")
    # this works, but if it takes a long time consider merging with `go tool covdata merge` first
    # https://go.dev/blog/integration-test-coverage#merging-raw-profiles-with-go-tool-covdata-merge
    run(["go", "tool", "covdata", "textfmt", "-i", coverage_dir, "-o", cov_text])

if __name__ == "__main__":
    main()
