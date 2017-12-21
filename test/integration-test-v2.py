#!/usr/bin/env python2.7
import atexit
import random
import shutil
import subprocess
import tempfile

import startservers

import chisel2
from chisel2 import auth_and_issue

exit_status = 1
tempdir = tempfile.mkdtemp()

def random_domain():
    """Generate a random domain for testing (to avoid rate limiting)."""
    return "rand.%x.xyz" % random.randrange(2**32)

def main():
    if not startservers.start(race_detection=True):
        raise Exception("startservers failed")

    test_multidomain()

    if not startservers.check():
        raise Exception("startservers.check failed")

    global exit_status
    exit_status = 0

def test_multidomain():
    auth_and_issue([random_domain(), random_domain()])

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
