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

def run(cmd, race_detection):
    e = os.environ.copy()
    e.setdefault("GORACE", "halt_on_error=1")
    # Note: Must use exec here so that killing this process kills the command.
    cmd = """exec ./bin/%s""" % cmd
    p = subprocess.Popen(cmd, shell=True, env=e)
    p.cmd = cmd
    return p

def start(race_detection):
    """Return True if everything builds and starts.

    Give up and return False if anything fails to build, or dies at
    startup. Anything that did start before this point can be cleaned
    up explicitly by calling stop(), or automatically atexit.
    """
    signal.signal(signal.SIGTERM, lambda _, __: stop())
    signal.signal(signal.SIGINT, lambda _, __: stop())
    global processes
    forwards = [
            [":19091", "publisher.boulder:9091"],
            [":19092", "va.boulder:9092"],
            [":19093", "ca.boulder:9093"],
            [":19094", "ra.boulder:9094"],
            [":19095", "sa.boulder:9095"],
            [":19096", "ca.boulder:9096"],
    ]
    if default_config_dir.startswith("test/config-next"):
        forwards.extend([[":19097", "va.boulder:9097"], [":19098", "va.boulder:9098"]])

    for srv in forwards:
        forward(srv[0], srv[1])
    progs = [
        # The gsb-test-srv needs to be started before the VA or its intial DB
        # update will fail and all subsequent lookups will be invalid
        'gsb-test-srv -apikey my-voice-is-my-passport',
        'boulder-sa --config %s' % os.path.join(default_config_dir, "sa.json"),
        'boulder-wfe --config %s' % os.path.join(default_config_dir, "wfe.json"),
        'boulder-ra --config %s' % os.path.join(default_config_dir, "ra.json"),
        'boulder-ca --config %s' % os.path.join(default_config_dir, "ca.json"),
        'boulder-va --config %s' % os.path.join(default_config_dir, "va.json"),
        'boulder-publisher --config %s' % os.path.join(default_config_dir, "publisher.json"),
        'ocsp-updater --config %s' % os.path.join(default_config_dir, "ocsp-updater.json"),
        'ocsp-responder --config %s' % os.path.join(default_config_dir, "ocsp-responder.json"),
        'ct-test-srv',
        'dns-test-srv',
        'mail-test-srv --closeFirst 5'
    ]
    if default_config_dir.startswith("test/config-next"):
        progs.extend([
            'boulder-va --config %s' % os.path.join(default_config_dir, "va-remote-a.json"),
            'boulder-va --config %s' % os.path.join(default_config_dir, "va-remote-b.json")
        ])
        # GSB doesn't like sharing databases so make sure the two remote VAs have a special place to put them
        if not os.path.exists("/tmp/gsb-a"):
            os.makedirs("/tmp/gsb-a")
        if not os.path.exists("/tmp/gsb-b"):
            os.makedirs("/tmp/gsb-b")
    if not install(race_detection):
        return False
    for prog in progs:
        try:
            processes.append(run(prog, race_detection))
        except Exception as e:
            print(e)
            return False
        if not check():
            # Don't keep building stuff if a server has already died.
            return False

    # Wait until all servers are up before returning to caller. This means
    # checking each server's debug port until it's available.
    while True:
        try:
            time.sleep(0.3)
            # If one of the servers has died, quit immediately.
            if not check():
                return False
            ports = range(8000, 8005) + [4000, 4430]
            if default_config_dir.startswith("test/config-next"):
                ports.extend([8011, 8012])
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
    # When we are about to exit, send SIGKILL to each subprocess and wait for
    # them to nicely die. This reflects the restart process in prod and allows
    # us to exercise the graceful shutdown code paths.
    # TODO(jsha): Switch to SIGTERM once we fix
    # https://github.com/letsencrypt/boulder/issues/2410 and remove AMQP, to
    # make shutdown less noisy.
    for p in processes:
        if p.poll() is None:
            p.send_signal(signal.SIGKILL)
    for p in processes:
        p.wait()
