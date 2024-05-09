# Test keys and certificates

This directory contains scripts and programs which generate keys and certificates for use in our integration tests. The keys and certificates themselves are stored in subdirectories of this one, so that they can be easily deleted and regenerated. The scripts do not regenerate a directory if it already exists, to allow the generated files to be re-used across many runs on a developer's machine.

The subdirectories include:

- webpki: Contains a PKI which emulates our publicly-trusted hierarchy, which can be loaded by the CA and other components to issue test end-entity certificates.
- ipki: Contains a PKI which emulates our internal hierarchy, which can be loaded by various components for use as gRPC mTLS credentials and more.

Each subdirectory is listed in this directory's .gitignore file. If you add a new directory, make sure you add it to the .gitignore file as well.

This script is invoked automatically by the `bsetup` container in our docker compose system. It is invoked automatically by `t.sh` and `tn.sh`. If you want to run it manually, the expected way to do so is:

```sh
$ docker compose up bsetup
[+] Running 0/1
Attaching to bsetup-1
bsetup-1  | Generating ipki/...
bsetup-1  | Generating webpki/...
bsetup-1 exited with code 0
```
