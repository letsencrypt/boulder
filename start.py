#!/usr/bin/python2.7 -u
"""
Run a local instance of Boulder for testing purposes.

This runs in non-monolithic mode and requires RabbitMQ on localhost.

Keeps servers alive until ^C. Exit non-zero if any servers fail to
start, or die before ^C.
"""

import errno
import os
import sys
import time

sys.path.append('./test')
import startservers

# Setup issuance hierarchy
startservers.setupHierarchy()

if not startservers.start(race_detection=False, fakeclock=None):
    sys.exit(1)
try:
    os.wait()

    # If we reach here, a child died early. Log what died:
    startservers.check()
    sys.exit(1)
except KeyboardInterrupt:
    print("\nstopping servers.")
except OSError as v:
    # Ignore EINTR, which happens when we get SIGTERM or SIGINT (i.e. when
    # someone hits Ctrl-C after running docker-compose up or start.py.
    if v.errno != errno.EINTR:
        raise
