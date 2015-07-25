import atexit
import os
import shutil
import signal
import subprocess
import tempfile


config = os.environ.get('BOULDER_CONFIG')
if config is None:
	config = 'test/boulder-config.json'
processes = []
tempdir = tempfile.mkdtemp()


def run(path):
    binary = os.path.join(tempdir, os.path.basename(path))
    goargs = '-race' if os.environ.get('GORACE') else ''
    cmd = 'go build %s -o %s ./%s' % (goargs, binary, path)
    print(cmd)
    subprocess.check_call(cmd, shell=True)
    def _ignore_sigint():
        signal.signal(signal.SIGINT, signal.SIG_IGN)
    p = subprocess.Popen(
        [binary, '--config', config],
        preexec_fn=_ignore_sigint)
    p.cmd = cmd
    print('started %s with pid %d' % (binary, p.pid))
    return p


def start():
    """Return True if everything builds and starts.

    Give up and return False if anything fails to build, or dies at
    startup. Anything that did start before this point can be cleaned
    up explicitly by calling stop(), or automatically atexit.
    """
    global processes
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
    return check()


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
    print "\n%d servers are running." % len(stillok)
    if busted:
        print "\n\nThese processes didn't start up successfully (check above for their output):"
        for p in busted:
            print "\t'%s' exited %d" % (p.cmd, p.returncode)
    processes = stillok
    return not busted


@atexit.register
def stop():
    for p in processes:
        p.kill()
    shutil.rmtree(tempdir)
