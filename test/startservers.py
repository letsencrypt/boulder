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

def run(cmd, race_detection, fakeclock):
    e = os.environ.copy()
    e.setdefault("GORACE", "halt_on_error=1")
    if fakeclock is not None:
        e.setdefault("FAKECLOCK", fakeclock)
    # Note: Must use exec here so that killing this process kills the command.
    cmd = """exec ./bin/%s""" % cmd
    p = subprocess.Popen(cmd, shell=True, env=e)
    p.cmd = cmd
    return p

def waitport(port, prog):
    """Wait until a port on localhost is open."""
    while True:
        try:
            time.sleep(0.1)
            # If one of the servers has died, quit immediately.
            if not check():
                return False
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(('localhost', port))
            s.close()
            break
        except socket.error as e:
            if e.errno == errno.ECONNREFUSED:
                print "Waiting for debug port %d (%s)" % (port, prog)
            else:
                raise
    return True

def start(race_detection, fakeclock=None):
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
            [8011, 'boulder-va --config %s' % os.path.join(default_config_dir, "va-remote-a.json")],
            [8012, 'boulder-va --config %s' % os.path.join(default_config_dir, "va-remote-b.json")],
        ])
    progs.extend([
        [8003, 'boulder-sa --config %s --addr :9095 --debug-addr :8003' % os.path.join(default_config_dir, "sa.json")],
        [8103, 'boulder-sa --config %s --addr :9195 --debug-addr :8103' % os.path.join(default_config_dir, "sa.json")],
        [4500, 'ct-test-srv --config test/ct-test-srv/ct-test-srv.json'],
        [8009, 'boulder-publisher --config %s --addr :9091 --debug-addr :8009' % os.path.join(default_config_dir, "publisher.json")],
        [8109, 'boulder-publisher --config %s --addr :9191 --debug-addr :8109' % os.path.join(default_config_dir, "publisher.json")],
        [9380, 'mail-test-srv --closeFirst 5 --cert test/mail-test-srv/localhost/cert.pem --key test/mail-test-srv/localhost/key.pem'],
        [8005, 'ocsp-responder --config %s' % os.path.join(default_config_dir, "ocsp-responder.json")],
        # The gsb-test-srv needs to be started before the VA or its intial DB
        # update will fail and all subsequent lookups will be invalid
        [6000, 'gsb-test-srv -apikey my-voice-is-my-passport'],
        [8053, 'challtestsrv --dns01 :8053,:8054 --management :8056 --http01 ""'],
        [8004, 'boulder-va --config %s --addr :9092 --debug-addr :8004' % os.path.join(default_config_dir, "va.json")],
        [8104, 'boulder-va --config %s --addr :9192 --debug-addr :8104' % os.path.join(default_config_dir, "va.json")],
        [8001, 'boulder-ca --config %s --ca-addr :9093 --ocsp-addr :9096 --debug-addr :8001' % os.path.join(default_config_dir, "ca.json")],
        [8101, 'boulder-ca --config %s --ca-addr :9193 --ocsp-addr :9196 --debug-addr :8101' % os.path.join(default_config_dir, "ca.json")],
        [8006, 'ocsp-updater --config %s' % os.path.join(default_config_dir, "ocsp-updater.json")],
        [8002, 'boulder-ra --config %s --addr :9094 --debug-addr :8002' % os.path.join(default_config_dir, "ra.json")],
        [8102, 'boulder-ra --config %s --addr :9194 --debug-addr :8102' % os.path.join(default_config_dir, "ra.json")],
        [4431, 'boulder-wfe2 --config %s' % os.path.join(default_config_dir, "wfe2.json")],
        [4000, 'boulder-wfe --config %s' % os.path.join(default_config_dir, "wfe.json")],
    ])
    for (port, prog) in progs:
        try:
            global processes
            processes.append(run(prog, race_detection, fakeclock))
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
