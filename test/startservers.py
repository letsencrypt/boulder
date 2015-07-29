import atexit
import BaseHTTPServer
import os
import shutil
import signal
import subprocess
import tempfile
import threading


class ToSServerThread(threading.Thread):
    class ToSHandler(BaseHTTPServer.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write("Do What Ye Will (An it Harm None).\n")
    def run(self):
        BaseHTTPServer.HTTPServer(("localhost", 4001), self.ToSHandler).serve_forever()


config = os.environ.get('BOULDER_CONFIG')
if config is None:
	config = 'test/boulder-config.json'
processes = []
tempdir = tempfile.mkdtemp()


def run(path):
    binary = os.path.join(tempdir, os.path.basename(path))

    buildcmd = 'GORACE="halt_on_error=1" go build -race -o %s ./%s' % (binary, path)
    print(buildcmd)
    subprocess.check_call(buildcmd, shell=True)

    srvcmd = [binary, '--config', config]
    p = subprocess.Popen(srvcmd)
    p.cmd = srvcmd
    print('started %s with pid %d' % (p.cmd, p.pid))
    return p


def start():
    """Return True if everything builds and starts.

    Give up and return False if anything fails to build, or dies at
    startup. Anything that did start before this point can be cleaned
    up explicitly by calling stop(), or automatically atexit.
    """
    global processes
    t = ToSServerThread()
    t.daemon = True
    t.start()
    for prog in [
            'cmd/boulder-wfe',
            'cmd/boulder-ra',
            'cmd/boulder-sa',
            'cmd/boulder-ca',
            'cmd/boulder-va',
            'test/dns-test-srv']:
        try:
            processes.append(run(prog))
        except Exception as e:
            print(e)
            return False
        if not check():
            # Don't keep building stuff if a server has already died.
            return False
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
    shutil.rmtree(tempdir)
