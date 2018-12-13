import atexit
import BaseHTTPServer
import errno
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time

default_config_dir = os.environ.get('BOULDER_CONFIG_DIR', '')
if default_config_dir == '':
    default_config_dir = 'test/config'

processes = []

def install(race_detection):
    # Pass empty BUILD_TIME and BUILD_ID flags to avoid constantly invalidating the
    # build cache with new BUILD_TIMEs, or invalidating it on merges with a new
    # BUILD_ID.
    cmd = "make GO_BUILD_FLAGS=''  "
    if race_detection:
        cmd = "make GO_BUILD_FLAGS='-race -tags \"integration\"'"

    return subprocess.call(cmd, shell=True) == 0

def run(cmd, race_detection, fakeclock, account_uri):
    e = os.environ.copy()
    e.setdefault("GORACE", "halt_on_error=1")
    if fakeclock:
        e.setdefault("FAKECLOCK", fakeclock)
    if account_uri:
        e.setdefault("ACCOUNT_URI", account_uri)
    # Note: Must use exec here so that killing this process kills the command.
    cmd = """exec %s""" % cmd
    p = subprocess.Popen(cmd, shell=True, env=e)
    p.cmd = cmd
    return p

def waitport(port, prog):
    """Wait until a port on localhost is open."""
    for _ in range(1000):
        try:
            time.sleep(0.1)
            # If one of the servers has died, quit immediately.
            if not check():
                return False
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(('localhost', port))
            s.close()
            return True
        except socket.error as e:
            if e.errno == errno.ECONNREFUSED:
                print "Waiting for debug port %d (%s)" % (port, prog)
            else:
                raise
    raise Exception("timed out waiting for debug port %d (%s)" % (port, prog))

def start(race_detection, fakeclock=None, account_uri=None):
    """Return True if everything builds and starts.

    Give up and return False if anything fails to build, or dies at
    startup. Anything that did start before this point can be cleaned
    up explicitly by calling stop(), or automatically atexit.
    """
    signal.signal(signal.SIGTERM, lambda _, __: stop())
    signal.signal(signal.SIGINT, lambda _, __: stop())
    if not install(race_detection):
        return False

    # Processes are in order of dependency: Each process should be started
    # before any services that intend to send it RPCs. On shutdown they will be
    # killed in reverse order.
    progs = []
    if default_config_dir.startswith("test/config-next"):
        # Run the two 'remote' VAs
        progs.extend([
            [8011, './bin/boulder-va --config %s' % os.path.join(default_config_dir, "va-remote-a.json")],
            [8012, './bin/boulder-va --config %s' % os.path.join(default_config_dir, "va-remote-b.json")],
        ])
    progs.extend([
        [53, './bin/sd-test-srv --listen :53'], # Service discovery DNS server
        [8003, './bin/boulder-sa --config %s --addr sa1.boulder:9095 --debug-addr :8003' % os.path.join(default_config_dir, "sa.json")],
        [8103, './bin/boulder-sa --config %s --addr sa2.boulder:9095 --debug-addr :8103' % os.path.join(default_config_dir, "sa.json")],
        [4500, './bin/ct-test-srv --config test/ct-test-srv/ct-test-srv.json'],
        [8009, './bin/boulder-publisher --config %s --addr publisher1.boulder:9091 --debug-addr :8009' % os.path.join(default_config_dir, "publisher.json")],
        [8109, './bin/boulder-publisher --config %s --addr publisher2.boulder:9091 --debug-addr :8109' % os.path.join(default_config_dir, "publisher.json")],
        [9380, './bin/mail-test-srv --closeFirst 5 --cert test/mail-test-srv/localhost/cert.pem --key test/mail-test-srv/localhost/key.pem'],
        [8005, './bin/ocsp-responder --config %s' % os.path.join(default_config_dir, "ocsp-responder.json")],
        # The gsb-test-srv needs to be started before the VA or its intial DB
        # update will fail and all subsequent lookups will be invalid
        [6000, './bin/gsb-test-srv -apikey my-voice-is-my-passport'],
        # NOTE(@cpu): We specify explicit bind addresses for -https01 and
        # --tlsalpn01 here to allow HTTPS HTTP-01 responses on 5001 for one
        # interface and TLS-ALPN-01 responses on 5001 for another interface. The
        # choice of which is used is controlled by mock DNS data added by the
        # relevant integration tests.
        [8053, 'pebble-challtestsrv --defaultIPv4 %s --defaultIPv6 "" --dns01 :8053,:8054 --management :8055 --http01 :5002 -https01 10.77.77.77:5001 --tlsalpn01 10.88.88.88:5001' % os.environ.get("FAKE_DNS")],
        [8004, './bin/boulder-va --config %s --addr va1.boulder:9092 --debug-addr :8004' % os.path.join(default_config_dir, "va.json")],
        [8104, './bin/boulder-va --config %s --addr va2.boulder:9092 --debug-addr :8104' % os.path.join(default_config_dir, "va.json")],
        [8001, './bin/boulder-ca --config %s --ca-addr ca1.boulder:9093 --ocsp-addr ca1.boulder:9096 --debug-addr :8001' % os.path.join(default_config_dir, "ca-a.json")],
        [8101, './bin/boulder-ca --config %s --ca-addr ca2.boulder:9093 --ocsp-addr ca2.boulder:9096 --debug-addr :8101' % os.path.join(default_config_dir, "ca-b.json")],
        [6789, './bin/akamai-test-srv --listen localhost:6789 --secret its-a-secret'],
        [8006, './bin/ocsp-updater --config %s' % os.path.join(default_config_dir, "ocsp-updater.json")],
        [8002, './bin/boulder-ra --config %s --addr ra1.boulder:9094 --debug-addr :8002' % os.path.join(default_config_dir, "ra.json")],
        [8102, './bin/boulder-ra --config %s --addr ra2.boulder:9094 --debug-addr :8102' % os.path.join(default_config_dir, "ra.json")],
        [4431, './bin/boulder-wfe2 --config %s' % os.path.join(default_config_dir, "wfe2.json")],
        [4000, './bin/boulder-wfe --config %s' % os.path.join(default_config_dir, "wfe.json")],
    ])
    for (port, prog) in progs:
        try:
            global processes
            processes.append(run(prog, race_detection, fakeclock, account_uri))
            if not waitport(port, prog):
                return False
        except Exception as e:
            print(e)
            return False
    print "All servers running. Hit ^C to kill."
    return True

def check():
    """Return true if all started processes are still alive.

    Log about anything that died.
    """
    global processes
    busted = []
    stillok = []
    for p in processes:
        if p.poll() is None:
            stillok.append(p)
        else:
            busted.append(p)
    if busted:
        print "\n\nThese processes exited early (check above for their output):"
        for p in busted:
            print "\t'%s' with pid %d exited %d" % (p.cmd, p.pid, p.returncode)
    processes = stillok
    return not busted


@atexit.register
def stop():
    # When we are about to exit, send SIGTERM to each subprocess and wait for
    # them to nicely die. This reflects the restart process in prod and allows
    # us to exercise the graceful shutdown code paths.
    global processes
    for p in reversed(processes):
        if p.poll() is None:
            p.send_signal(signal.SIGTERM)
            p.wait()
    processes = []
