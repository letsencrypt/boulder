import atexit
import os
import signal
import subprocess

from helpers import waithealth, waitport, config_dir


SERVICES = {
    "boulder-remoteva-a": {
        "debug_port": 8011,
        "grpc_addr": "rva1.service.consul:9097",
        "cmd": ("./bin/boulder", "boulder-remoteva", "--config", os.path.join(config_dir, "va-remote-a.json")),
    },
    "boulder-remoteva-b": {
        "debug_port": 8012,
        "grpc_addr": "rva1.service.consul:9098",
        "cmd": ("./bin/boulder", "boulder-remoteva", "--config", os.path.join(config_dir, "va-remote-b.json")),
    },
    "boulder-sa-1": {
        "debug_port": 8003,
        "grpc_addr": "sa1.service.consul:9095",
        "cmd": ("./bin/boulder", "boulder-sa", "--config", os.path.join(config_dir, "sa.json"), "--addr", "sa1.service.consul:9095", "--debug-addr", ":8003"),
    },
    "boulder-sa-2": {
        "debug_port": 8103,
        "grpc_addr": "sa2.service.consul:9095",
        "cmd": ("./bin/boulder", "boulder-sa", "--config", os.path.join(config_dir, "sa.json"), "--addr", "sa2.service.consul:9095", "--debug-addr", ":8103"),
    },
    "ct-test-srv": {
        "debug_port": 4500,
        "cmd": ("./bin/ct-test-srv", "--config", "test/ct-test-srv/ct-test-srv.json"),
    },
    "boulder-publisher-1": {
        "debug_port": 8009,
        "grpc_addr": "publisher1.service.consul:9091",
        "cmd": ("./bin/boulder", "boulder-publisher", "--config", os.path.join(config_dir, "publisher.json"), "--addr", "publisher1.service.consul:9091", "--debug-addr", ":8009"),
    },
    "boulder-publisher-2": {
        "debug_port": 8109,
        "grpc_addr": "publisher2.service.consul:9091",
        "cmd": ("./bin/boulder", "boulder-publisher", "--config", os.path.join(config_dir, "publisher.json"), "--addr", "publisher2.service.consul:9091", "--debug-addr", ":8109"),
    },
    "mail-test-srv": {
        "debug_port": 9380,
        "cmd": ("./bin/mail-test-srv", "--closeFirst", "5", "--cert", "test/mail-test-srv/localhost/cert.pem", "--key", "test/mail-test-srv/localhost/key.pem"),
    },
    "ocsp-responder": {
        "debug_port": 8005,
        "cmd": ("./bin/boulder", "ocsp-responder", "--config", os.path.join(config_dir, "ocsp-responder.json")),
        "deps": ("boulder-ra-1", "boulder-ra-2"),
    },
    "boulder-va-1": {
        "debug_port": 8004,
        "grpc_addr": "va1.service.consul:9092",
        "cmd": ("./bin/boulder", "boulder-va", "--config", os.path.join(config_dir, "va.json"), "--addr", "va1.service.consul:9092", "--debug-addr", ":8004"),
        "deps": ("boulder-remoteva-a", "boulder-remoteva-b"),
    },
    "boulder-va-2": {
        "debug_port": 8104,
        "grpc_addr": "va2.service.consul:9092",
        "cmd": ("./bin/boulder", "boulder-va", "--config", os.path.join(config_dir, "va.json"), "--addr", "va2.service.consul:9092", "--debug-addr", ":8104"),
        "deps": ("boulder-remoteva-a", "boulder-remoteva-b"),
    },
    "boulder-ca-a": {
        "debug_port": 8001,
        "grpc_addr": "ca1.service.consul:9093",
        "cmd": ("./bin/boulder", "boulder-ca", "--config", os.path.join(config_dir, "ca-a.json"), "--ca-addr", "ca1.service.consul:9093", "--debug-addr", ":8001"),
        "deps": ("boulder-sa-1", "boulder-sa-2"),
    },
    "boulder-ca-b": {
        "debug_port": 8101,
        "grpc_addr": "ca2.service.consul:9093",
        "cmd": ("./bin/boulder", "boulder-ca", "--config", os.path.join(config_dir, "ca-b.json"), "--ca-addr", "ca2.service.consul:9093", "--debug-addr", ":8101"),
        "deps": ("boulder-sa-1", "boulder-sa-2"),
    },
    "akamai-test-srv": {"debug_port": 6789, "cmd": ("./bin/akamai-test-srv", "--listen", "localhost:6789", "--secret", "its-a-secret")},
    "akamai-purger": {
        "debug_port": 9666,
        "cmd": ("./bin/boulder", "akamai-purger", "--config", os.path.join(config_dir, "akamai-purger.json")),
        "deps": ("akamai-test-srv",),
    },
    "s3-test-srv": {"debug_port": 7890, "cmd": ("./bin/s3-test-srv", "--listen", "localhost:7890")},
    "crl-storer": {"debug_port": 9667, "cmd": ("./bin/boulder", "crl-storer", "--config", os.path.join(config_dir, "crl-storer.json")), "deps": ("s3-test-srv",)},
    "crl-updater": {
        "debug_port": 8021,
        "cmd": ("./bin/boulder", "crl-updater", "--config", os.path.join(config_dir, "crl-updater.json")),
        "deps": ("boulder-ca-a", "boulder-ca-b", "boulder-sa-1", "boulder-sa-2", "crl-storer"),
    },
    "boulder-ra-1": {
        "debug_port": 8002,
        "grpc_addr": "ra1.service.consul:9094",
        "cmd": ("./bin/boulder", "boulder-ra", "--config", os.path.join(config_dir, "ra.json"), "--addr", "ra1.service.consul:9094", "--debug-addr", ":8002"),
        "deps": ("boulder-sa-1", "boulder-sa-2", "boulder-ca-a", "boulder-ca-b", "boulder-va-1", "boulder-va-2", "akamai-purger", "boulder-publisher-1", "boulder-publisher-2"),
    },
    "boulder-ra-2": {
        "debug_port": 8102,
        "grpc_addr": "ra2.service.consul:9094",
        "cmd": ("./bin/boulder", "boulder-ra", "--config", os.path.join(config_dir, "ra.json"), "--addr", "ra2.service.consul:9094", "--debug-addr", ":8102"),
        "deps": ("boulder-sa-1", "boulder-sa-2", "boulder-ca-a", "boulder-ca-b", "boulder-va-1", "boulder-va-2", "akamai-purger", "boulder-publisher-1", "boulder-publisher-2"),
    },
    "bad-key-revoker": {
        "debug_port": 8020,
        "cmd": ("./bin/boulder", "bad-key-revoker", "--config", os.path.join(config_dir, "bad-key-revoker.json")),
        "deps": ("boulder-ra-1", "boulder-ra-2", "mail-test-srv"),
    },
    "nonce-service-taro": {
        "debug_port": 8111,
        "grpc_addr": "nonce1.service.consul:9101",
        "cmd": (
            "./bin/boulder",
            "nonce-service",
            "--config",
            os.path.join(config_dir, "nonce-a.json"),
            "--addr",
            "10.77.77.77:9101",
            "--debug-addr",
            ":8111",
        ),
    },
    "nonce-service-zinc": {
        "debug_port": 8112,
        "grpc_addr": "nonce2.service.consul:9101",
        "cmd": (
            "./bin/boulder",
            "nonce-service",
            "--config",
            os.path.join(config_dir, "nonce-b.json"),
            "--addr",
            "10.88.88.88:9101",
            "--debug-addr",
            ":8112",
        ),
    },
    "boulder-wfe2": {
        "debug_port": 4001,
        "cmd": ("./bin/boulder", "boulder-wfe2", "--config", os.path.join(config_dir, "wfe2.json")),
        "deps": ("boulder-ra-1", "boulder-ra-2", "boulder-sa-1", "boulder-sa-2", "nonce-service-taro", "nonce-service-zinc"),
    },
    "log-validator": {"debug_port": 8016, "cmd": ("./bin/boulder", "log-validator", "--config", os.path.join(config_dir, "log-validator.json"))},
}


def _service_toposort(services):
    """Yields Service objects in topologically sorted order.

    No service will be yielded until every service listed in its deps value
    has been yielded.
    """
    ready = set([s for s in services if not services[s].get("deps")])
    blocked = set(services) - ready
    done = set()
    while ready:
        service = ready.pop()
        yield service
        done.add(service)
        new = set([s for s in blocked if all([d in done for d in services[s].get("deps")])])
        ready |= new
        blocked -= new
    if blocked:
        print("WARNING: services with unsatisfied dependencies:")
        for s in blocked:
            print(s, ":", services[s].get("deps"))
        raise Exception("Unable to satisfy service dependencies")


processes = []

# NOTE(@cpu): We manage the challSrvProcess separately from the other global
# processes because we want integration tests to be able to stop/start it (e.g.
# to run the load-generator).
challSrvProcess = None


def setupHierarchy():
    """Set up the issuance hierarchy. Must have called install() before this."""
    e = os.environ.copy()
    e.setdefault("GOBIN", "%s/bin" % os.getcwd())
    try:
        subprocess.check_output(["go", "run", "test/cert-ceremonies/generate.go"], env=e)
    except subprocess.CalledProcessError as e:
        print(e.output)
        raise


def install(race_detection):
    # Pass empty BUILD_TIME and BUILD_ID flags to avoid constantly invalidating the
    # build cache with new BUILD_TIMEs, or invalidating it on merges with a new
    # BUILD_ID.
    go_build_flags = '-tags "integration"'
    if race_detection:
        go_build_flags += " -race"

    return subprocess.call(["/usr/bin/make", "GO_BUILD_FLAGS=%s" % go_build_flags]) == 0


def run(cmd, fakeclock):
    e = os.environ.copy()
    e.setdefault("GORACE", "halt_on_error=1")
    if fakeclock:
        e.setdefault("FAKECLOCK", fakeclock)
    p = subprocess.Popen(cmd, env=e)
    p.cmd = cmd
    return p


def start(fakeclock):
    """Return True if everything builds and starts.

    Give up and return False if anything fails to build, or dies at
    startup. Anything that did start before this point can be cleaned
    up explicitly by calling stop(), or automatically atexit.
    """
    signal.signal(signal.SIGTERM, lambda _, __: stop())
    signal.signal(signal.SIGINT, lambda _, __: stop())

    # Start the pebble-challtestsrv first so it can be used to resolve DNS for
    # gRPC.
    startChallSrv()

    # Processes are in order of dependency: Each process should be started
    # before any services that intend to send it RPCs. On shutdown they will be
    # killed in reverse order.
    for service in _service_toposort(SERVICES):
        print("Starting service", service)
        try:
            global processes
            p = run(SERVICES[service]["cmd"], fakeclock)
            processes.append(p)
            if SERVICES[service].get("grpc_addr") is not None:
                waithealth(" ".join(p.args), SERVICES[service]["grpc_addr"])
            else:
                if not waitport(SERVICES[service]["debug_port"], " ".join(p.args), perTickCheck=check):
                    return False
        except Exception as e:
            print(f"Error starting service {service}: {e}")
            return False

    print("All servers running. Hit ^C to kill.")
    return True


def check():
    """Return true if all started processes are still alive.

    Log about anything that died. The pebble-challtestsrv is not considered when
    checking processes.
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
        print("\n\nThese processes exited early (check above for their output):")
        for p in busted:
            print("\t'%s' with pid %d exited %d" % (p.cmd, p.pid, p.returncode))
    processes = stillok
    return not busted


def startChallSrv():
    """
    Start the pebble-challtestsrv and wait for it to become available. See also
    stopChallSrv.
    """
    global challSrvProcess
    if challSrvProcess is not None:
        raise Exception("startChallSrv called more than once")

    # NOTE(@cpu): We specify explicit bind addresses for -https01 and
    # --tlsalpn01 here to allow HTTPS HTTP-01 responses on 443 for on interface
    # and TLS-ALPN-01 responses on 443 for another interface. The choice of
    # which is used is controlled by mock DNS data added by the relevant
    # integration tests.
    challSrvProcess = run(
        [
            "pebble-challtestsrv",
            "--defaultIPv4",
            os.environ.get("FAKE_DNS"),
            "-defaultIPv6",
            "",
            "--dns01",
            ":8053,:8054",
            "--management",
            ":8055",
            "--http01",
            "10.77.77.77:80",
            "-https01",
            "10.77.77.77:443",
            "--tlsalpn01",
            "10.88.88.88:443",
        ],
        None,
    )
    # Wait for the pebble-challtestsrv management port.
    if not waitport(8055, " ".join(challSrvProcess.args)):
        return False


def stopChallSrv():
    """
    Stop the running pebble-challtestsrv (if any) and wait for it to terminate.
    See also startChallSrv.
    """
    global challSrvProcess
    if challSrvProcess is None:
        return
    if challSrvProcess.poll() is None:
        challSrvProcess.send_signal(signal.SIGTERM)
        challSrvProcess.wait()
    challSrvProcess = None


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

    # Also stop the challenge test server
    stopChallSrv()
