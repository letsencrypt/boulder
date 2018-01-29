Boulder's test environment contains three separate PKIs: one for WFE (simulating
the public WebPKI), one for gRPC (simulating an internal PKI), and one for
issuance. In live deployment, the issuance PKI is a member of the global WebPKI,
but we simulate them as separate PKIs here.

The PKI used by WFE is under test/wfe-tls/, with test/wfe-tls/minica.pem serving
as the root. There are no intermediates. Setting test/wfe-tls/minica.pem as
a trusted root is sufficient to connect to the WFE over HTTPS. Currently there
is only one end-entity certificate in this PKI, and that's all we expect to
need. To validate HTTPS connections to a test-mode WFE in Python, set the environment
variable `REQUESTS_CA_BUNDLE`. For Node, set `NODE_EXTRA_CA_CERTS`. These
variables should be set to `/path/to/boulder/test/wfe-tls/minica.pem` (but only
in testing environments!). Note that in the Python case, setting this environment
variable may break HTTPS connections to non-WFE destinations. If causes problems
for you, you may need to create a combined bundle containing
`test/wfe-tls/minica.pem` in addition to the other relevant root certificates.

The gRPC PKI is under test/grpc-creds/. Each Boulder component has its own hostname
(even though right now all those hostnames resolve to 127.0.0.1 in test). For
each Boulder hostname, there is a directory under test/grpc-creds/ containing a
certificate and private key.

To issue new certificates in the WFE or gRPC PKI, install
https://github.com/jsha/minica, cd to the directory containing minica.pem for
the PKI you want to issue in, and run `minica -domains YOUR_NEW_DOMAIN`.

The issuance PKI consists of a root and two intermediates. Certificates issued
by Boulder tests are issued from the second of these two intermediates. During
tests, the keys are loaded into SoftHSM in a Docker container named
"bhsm". Boulder uses pkcs11-proxy to communicate with SoftHSM running in that
container and request signature operations, simulating use of a real HSM. The
.json files in the issuance PKI provide the parameters used to login to the
simulated PKCS#11 token (aka HSM).

Root:
   test-root.pem, test-root.key, test-root.key.der, test-root.key-pkcs11.json

Intermediate 1 (happy hacker fake CA):
   test-ca.der test-ca.key test-ca.key.der test-ca.key-pkcs11.json test-ca.pem

Intermediate 2 (h2ppy h2cker fake CA):
   test-ca2.key test-ca2.pem
