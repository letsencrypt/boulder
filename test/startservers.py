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


class ToSServerThread(threading.Thread):
    class ToSHandler(BaseHTTPServer.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write("Do What Ye Will (An it Harm None).\n")
    def run(self):
        try:
            BaseHTTPServer.HTTPServer(("localhost", 4001), self.ToSHandler).serve_forever()
        except Exception as e:
            print "Problem starting ToSServer: %s" % e
            sys.exit(1)


config = os.environ.get('BOULDER_CONFIG')
if config is None:
    config = 'test/boulder-config.json'
processes = []


def install(progs, race_detection):
    cmd = "go install"
    if race_detection:
        cmd = """go install -race"""

    for prog in progs:
        cmd += " ./" + prog
    p = subprocess.Popen(cmd, shell=True)
    out, err = p.communicate()
    if p.returncode != 0:
        sys.stderr.write("unable to run go install: %s\n" % cmd)
        if out:
            sys.stderr.write("stdout:\n" + out + "\n")
        if err:
            sys.stderr.write("stderr: \n" + err + "\n")
        return False
    print('installed %s with pid %d' % (cmd, p.pid))
    return True

def run(path, race_detection):
    binary = os.path.basename(path)
    # Note: Must use exec here so that killing this process kills the command.
    cmd = """GORACE="halt_on_error=1" exec %s --config %s""" % (binary, config)
    p = subprocess.Popen(cmd, shell=True)
    p.cmd = cmd
    print('started %s with pid %d' % (p.cmd, p.pid))
    return p

def start(race_detection):
    """Return True if everything builds and starts.

    Give up and return False if anything fails to build, or dies at
    startup. Anything that did start before this point can be cleaned
    up explicitly by calling stop(), or automatically atexit.
    """
    global processes
    t = ToSServerThread()
    t.daemon = True
    t.start()
    progs = [
        'cmd/boulder-wfe',
        'cmd/boulder-ra',
        'cmd/boulder-sa',
        'cmd/boulder-ca',
        'cmd/boulder-va',
        'cmd/ocsp-responder',
        'test/dns-test-srv'
    ]
    if not install(progs, race_detection):
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
    # seconds.
    while True:
        try:
            # If one of the servers has died, quit immediately.
            if not check():
                return False
            for debug_port in range(8000, 8005):
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect(('localhost', debug_port))
                s.close()
            break
        except socket.error as e:
            if e.errno == errno.ECONNREFUSED:
                print "Waiting for debug port %d" % debug_port
            else:
                raise
        time.sleep(1)

    # Some servers emit extra text after their debug server is open. Sleep 1
    # second so the "servers running" message comes last.
    time.sleep(1)
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
    for p in processes:
        if p.poll() is None:
            p.kill()
