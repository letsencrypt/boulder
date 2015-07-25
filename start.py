#!/usr/bin/env python2.7
"""
Run a local instance of Boulder for testing purposes.

This runs in non-monolithic mode and requires RabbitMQ on localhost.

Keeps servers alive until ^C or 100K seconds elapse. Exits non-zero if
any servers fail to start, or die before timer/^C.
"""

import sys
import time

sys.path.append('./test')
import startservers

if not startservers.start():
    sys.exit(1)
try:
    time.sleep(100000)
except KeyboardInterrupt:
    pass
if not startservers.check():
    sys.exit(1)
print "stopping servers."
