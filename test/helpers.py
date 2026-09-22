import atexit
import base64
import errno
import glob
import os
import random
import re
import requests
import shutil
import socket
import subprocess
import tempfile
import time
import urllib

import challtestsrv

challSrv = challtestsrv.ChallTestServer()
tempdir = tempfile.mkdtemp()

@atexit.register
def stop():
    shutil.rmtree(tempdir)

config_dir = os.environ.get('BOULDER_CONFIG_DIR', '')
if config_dir == '':
    raise Exception("BOULDER_CONFIG_DIR was not set")
CONFIG_NEXT = config_dir.startswith("test/config-next")

def temppath(name):
    """Creates and returns a closed file inside the tempdir."""
    f = tempfile.NamedTemporaryFile(
        dir=tempdir,
        suffix='.{0}'.format(name),
        mode='w+',
        delete=False
    )
    f.close()
    return f

def fakeclock(date):
    return date.strftime("%a %b %d %H:%M:%S UTC %Y")

def random_domain():
    """Generate a random domain for testing (to avoid rate limiting)."""
    return "rand.%x.xyz" % random.randrange(2**32)

def run(cmd, **kwargs):
    return subprocess.check_call(cmd, stderr=subprocess.STDOUT, **kwargs)

def waitport(port, prog, perTickCheck=None):
    """Wait until a port on localhost is open."""
    for _ in range(1000):
        try:
            time.sleep(0.1)
            if perTickCheck is not None and not perTickCheck():
                return False
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(('localhost', port))
            s.close()
            return True
        except socket.error as e:
            if e.errno == errno.ECONNREFUSED:
                print("Waiting for debug port %d (%s)" % (port, prog))
            else:
                raise
    raise(Exception("timed out waiting for debug port %d (%s)" % (port, prog)))

def waithealth(prog, addr, host_override):
    if type(addr) == int:
        addr = "localhost:%d" % (addr)

    subprocess.check_call([
        './bin/health-checker',
        '-addr', addr,
        '-host-override', host_override,
        '-config', os.path.join(config_dir, 'health-checker.json')])
