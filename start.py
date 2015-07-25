#!/usr/bin/env python2.7
"""
Run a local instance of Boulder for testing purposes.

This runs in non-monolithic mode and requires RabbitMQ on localhost.

Keeps servers alive until ^C or 100K seconds elapse. Exits non-zero if
any servers fail to start, or die before timer/^C.
"""

import os
import signal
import sys
import time

sys.path.append('./test')
import startservers


MAX_RUNTIME = 100000


class Alarm(Exception):
    pass


if not startservers.start():
    sys.exit(1)
try:
    time.sleep(1)
    print("All servers are running. To stop, hit ^C or wait %d seconds." % MAX_RUNTIME)

    def handler(*args):
        raise Alarm
    signal.signal(signal.SIGALRM, handler)
    signal.alarm(MAX_RUNTIME)
    os.wait()

    # If we reach here, a child died early. Log what died:
    startservers.check()
    sys.exit(1)
except KeyboardInterrupt, Alarm:
    signal.alarm(0)
    print "\nstopping servers."
