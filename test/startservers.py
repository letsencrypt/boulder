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
listenProcesses = []

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

def start(race_detection, fakeclock=None):
    """Return True if everything builds and starts.

    Give up and return False if anything fails to build, or dies at
    startup. Anything that did start before this point can be cleaned
    up explicitly by calling stop(), or automatically atexit.
    """
    signal.signal(signal.SIGTERM, lambda _, __: stop())
    signal.signal(signal.SIGINT, lambda _, __: stop())
    global processes
    progs = [
        'boulder-sa --config %s' % os.path.join(default_config_dir, "sa.json"),
        'ct-test-srv',
        'boulder-publisher --config %s' % os.path.join(default_config_dir, "publisher.json"),
        'mail-test-srv --closeFirst 5 --cert test/mail-test-srv/localhost/cert.pem --key test/mail-test-srv/localhost/key.pem',
        'ocsp-responder --config %s' % os.path.join(default_config_dir, "ocsp-responder.json"),
        # The gsb-test-srv needs to be started before the VA or its intial DB
        # update will fail and all subsequent lookups will be invalid
        'gsb-test-srv -apikey my-voice-is-my-passport',
        'dns-test-srv',
        'boulder-va --config %s' % os.path.join(default_config_dir, "va.json"),
        'boulder-ca --config %s' % os.path.join(default_config_dir, "ca.json"),
        'ocsp-updater --config %s' % os.path.join(default_config_dir, "ocsp-updater.json"),
        'boulder-ra --config %s' % os.path.join(default_config_dir, "ra.json"),
        'boulder-wfe2 --config %s' % os.path.join(default_config_dir, "wfe2.json"),
        'boulder-wfe --config %s' % os.path.join(default_config_dir, "wfe.json"),
    ]
    if default_config_dir.startswith("test/config-next"):
        # Run the two 'remote' VAs
        progs.extend([
            'boulder-va --config %s' % os.path.join(default_config_dir, "va-remote-a.json"),
            'boulder-va --config %s' % os.path.join(default_config_dir, "va-remote-b.json")
        ])
    if not install(race_detection):
        return False
    for prog in progs:
        try:
            processes.append(run(prog, race_detection, fakeclock))
        except Exception as e:
            print(e)
            return False
        if not check():
            # Don't keep building stuff if a server has already died.
            return False
        time.sleep(0.3)

    # Wait until all servers are up before returning to caller. This means
    # checking each server's debug port until it's available.
    while True:
        try:
            time.sleep(0.3)
            # If one of the servers has died, quit immediately.
            if not check():
                return False
            ports = range(8000, 8005) + [4000, 4001, 4430, 4431]
            if default_config_dir.startswith("test/config-next"):
                # Add the two 'remote' VA debug ports
                ports.extend([8011, 8012])
            # Add the wfe v2 debug port
            ports.extend([8013])
            for debug_port in ports:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect(('localhost', debug_port))
                s.close()
            break
        except socket.error as e:
            if e.errno == errno.ECONNREFUSED:
                print "Waiting for debug port %d" % debug_port
            else:
                raise

    # Some servers emit extra text after their debug server is open. Sleep 1
    # second so the "servers running" message comes last.
    time.sleep(1)
    print "All servers running. Hit ^C to kill."
    return True

def forward(listen, speak):
    """Add a TCP forwarder between gRPC client and server to simulate failures."""
    cmd = """exec listenbuddy -listen %s -speak %s""" % (listen, speak)
    p = subprocess.Popen(cmd, shell=True)
    p.cmd = cmd
    print('started %s with pid %d' % (p.cmd, p.pid))
    global listenProcesses
    listenProcesses.append(p)

def bounce_forward():
    """Kill all forwarded TCP connections."""
    global listenProcesses
    for p in listenProcesses:
        p.send_signal(signal.SIGUSR1)

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
    for p in processes:
        p.wait()
    processes = []
