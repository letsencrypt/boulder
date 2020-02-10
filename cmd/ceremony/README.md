# `ceremony`

```
ceremony --config path/to/config.yml
```

`ceremony` is a tool designed for Certificate Authority specific key and certificate ceremonies. The main design principle is that unlike most ceremony tooling there is a single user input, a configuration file, which is required to complete a root, intermediate, or key ceremony. The goal is to make ceremonies as simple as possible and allow for simple verification of a single file, instead of verification of a large number of independent commands.

`ceremony` operates in one of three modes
* `root` - generates a signing key on HSM and creates a self-signed root certificate that uses the generated key, outputting a PEM public key, and a PEM certificate
* `intermediate` - creates a intermediate certificate and signs it using a signing key already on a HSM, outputting a PEM certificate
* `key` - generates a signing key on HSM, outputting a PEM public key

These modes are set in the `ceremony-type` field of the configuration file.

## Configuration format

`ceremony` uses YAML for its configuration file, mainly as it allows for commenting.

| Field | Ceremony Type | Description |
| --- | --- | --- |
| `pkcs11-module` | All | Path to the PKCS#11 module to use to communicate with a HSM. |
| `ceremony-type` | All | Specifies what type of ceremony to do, either `root`, `intermediate`, or `key`. |
| `key-slot` | All | Specifies which HSM object slot the signing key is in/should be stored in. |
| `key-label` | All | Specifies the HSM object label for the signing key. |
| `key-id` | `intermediate` | Specifies the HSM object ID for the signing key to be used. |
| `key-type` | `root` and `key` | Specifies the type of key to be generated, either `rsa` or `ecdsa`. If `rsa` the generated key will have a 2048 bit modulus and an exponent of 65537. If `ecdsa` the curve is specified by `ecdsa-curve`. |
| `ecdsa-curve` | `root` and `key` | Specifies the ECDSA curve to use when generating key, either `P-224`, `P-256`, `P-384`, or `P-521`. |
| `public-key-path` | All | Path store PEM public key for generated signing key in `ceremony-type`s `root` and `key`, and path to PEM subject public key in `ceremony-type` `intermediate`. |
| `certificate-path` | `root` and `intermediate` | Path to store signed PEM certificate. |
| `issuer-path` | `intermediate` | Path to PEM issuer certificate. |
| `certificate-profile` | `root` and `intermediate` | Profile for certificate, [format defined below](#Certificate-profile-format) |

### Example configs

#### Root ceremony

```yaml
pkcs11-module: /usr/lib/opensc-pkcs11.so
ceremony-type: root
key-slot: 0
key-label: root signing key
key-type: ecdsa
ecdsa-curve: P-384
public-key-path: /home/user/root-signing-pub.pem
certificate-path: /home/user/root-cert.pem
issuer-path: /home/user/root-cert.pem
certificate-profile:
    signature-algorithm: ECDSAWithSHA384
    common-name: CA intermediate
    organization: good guys
    country: US
    not-before: 2020-01-01 12:00:00
    not-after: 2040-01-01 12:00:00
```

This config generates a ECDSA P-384 key in the HSM with the object label `root signing key` and uses this key to sign a self-signed certificate. The public key for the key generated is written to `/home/user/root-signing-pub.pem` and the certificate is written to `/home/user/root-cert.pem`.

#### Intermediate ceremony

```yaml
pkcs11-module: /usr/lib/opensc-pkcs11.so
ceremony-type: intermediate
key-slot: 0
key-label: root signing key
key-id: ffff
public-key-path: /home/user/intermediate-signing-pub.pem
certificate-path: /home/user/intermediate-cert.pem
issuer-path: /home/user/root-cert.pem
certificate-profile:
    signature-algorithm: ECDSAWithSHA384
    common-name: CA root
    organization: good guys
    country: US
    not-before: 2020-01-01 12:00:00
    not-after: 2040-01-01 12:00:00
    ocsp-url: http://good-guys.com/ocsp
    crl-url:  http://good-guys.com/crl
    issuer-url:  http://good-guys.com/root
    policy-oids:
        - 1.2.3
        - 5.4.3.2.1
```

This config generates an intermediate certificate signed by a key in the HSM, identified by the object label `root signing key` and the object ID `ffff`. The subject key used is taken from `/home/user/intermediate-signing-pub.pem` and the issuer is `/home/user/root-cert.pem`, the resulting certificate is written to `/home/user/intermediate-cert.pem`.

#### Key ceremony

```yaml
pkcs11-module: /usr/lib/opensc-pkcs11.so
ceremony-type: root
key-slot: 0
key-label: intermediate signing key
key-type: ecdsa
ecdsa-curve: P-384
public-key-path: /home/user/intermediate-signing-pub.pem
```

This config generates an ECDSA P-384 key in the HSM with the object label `intermediate signing key`. The public key is written to `/home/user/intermediate-signing-pub.pem`.

### Certificate profile format

The certificate profile defines a restricted set of fields that are used to generate root and intermediate certificates.

| Field | Description |
| --- | --- |
| `signature-algorithm` | Specifies the signing algorithm to use, one of `SHA256WithRSA`, `SHA384WithRSA`, `SHA512WithRSA`, `ECDSAWithSHA256`, `ECDSAWithSHA384`, `ECDSAWithSHA512` |
| `common-name` | Specifies the subject commonName |
| `organization` | Specifies the subject organization |
| `country` | Specifies the subject country |
| `not-before` | Specifies the certificate notBefore date, in the format `2006-01-02 15:04:05`. The time will be interpreted as UTC. |
| `not-after` | Specifies the certificate notAfter date, in the format `2006-01-02 15:04:05`. The time will be interpreted as UTC. |
| `ocsp-url` | Specifies the AIA OCSP responder URL |
| `crl-url` | Specifies the cRLDistributionPoints URL |
| `issuer-url` | Specifies the AIA caIssuer URL |
| `policy-oids` | Specifies the contents of the certificatePolicies extension |
