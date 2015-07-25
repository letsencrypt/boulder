#!/usr/bin/env python2.7
"""
Run a local instance of Boulder for testing purposes.

This runs in non-monolithic mode and requires RabbitMQ on localhost.

Keeps servers alive until ^C. Exit non-zero if any servers fail to
start, or die before ^C.
"""

import os
import sys
import time

sys.path.append('./test')
import startservers


if not startservers.start():
    sys.exit(1)
try:
    time.sleep(1)
    print("All servers are running. To stop, hit ^C.")

    os.wait()

    # If we reach here, a child died early. Log what died:
    startservers.check()
    sys.exit(1)
except KeyboardInterrupt:
    print "\nstopping servers."
