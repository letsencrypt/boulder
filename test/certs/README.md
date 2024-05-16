# Test keys and certificates

## Dynamically-Generated PKIs

This directory contains scripts and programs which generate PKIs (collections of
keys and certificates) for use in our integration tests. Each PKI has its own
subdirectory. The scripts do not regenerate a directory if it already exists, to
allow the generated files to be re-used across many runs on a developer's
machine. To force the scripts to regenerate a PKI, simply delete its whole
directory.

This script is invoked automatically by the `bsetup` container in our docker
compose system. It is invoked automatically by `t.sh` and `tn.sh`. If you want
to run it manually, the expected way to do so is:

```sh
$ docker compose up bsetup
[+] Running 0/1
Attaching to bsetup-1
bsetup-1  | Generating ipki/...
bsetup-1  | Generating webpki/...
bsetup-1 exited with code 0
```

To add new certificates to an existing PKI, edit the script which generates that
PKI's subdirectory. To add a whole new PKI, create a new generation script,
execute that script from this directory's top-level `generate.sh`, and add the
new subdirectory to this directory's `.gitignore` file.

### webpki

The "webpki" PKI emulates our publicly-trusted hierarchy. It consists of RSA and
ECDSA roots, several intermediates and cross-signed intermediates, and CRLs.
These certificates and their keys are generated using the `ceremony` tool. The
private keys are stored in SoftHSM in the `.softhsm-tokens` subdirectory.

This PKI is loaded by the CA, RA, and other components. It is used as the
issuance hierarchy for all end-entity certificates issued as part of the
integration tests.

### ipki

The "ipki" PKI emulates our internal PKI that the various Boulder services use
to authenticate each other when establishing gRPC connections. It includes one
certificate for each service which participates in our gRPC cluster. Some of
these certificates (for the services that we run multiple copies of) have
multiple names, so the same certificate can be loaded by each copy of that
service.

This PKI is loaded by virtually every Boulder component.

## Other Test PKIs

A variety of other PKIs (collections of keys and certificates) exist in this
repository for the sake of unit and integration testing. We list them here as a
TODO-list of PKIs to remove and clean up:

- challtestsrv DoH: Our fake DNS challenge test server (which fulfills DNS-01
  challenges during integration tests) can negotiate DoH handshakes. The key and
  cert is uses for this are currently generated as part of the ipki directory,
  but are fundamentally different from that PKI and should be moved.
- wfe-tls: The //test/wfe-tls/ directory holds the key and certificate which the
  WFE uses to negotiate TLS handshakes with API clients.
- redis: The //test/redis-tls/ directory holds the key and certificate used by
  our test redis cluster. This should probably be moved into the ipki directory.
- unit tests: the //test/hierarchy/ directory holds a variety of certificates
  used by unit tests. These should be replaced by certs which the unit tests
  dynamically generate in-memory, rather than loading from disk.
