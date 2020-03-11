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

`ceremony` uses YAML for its configuration file, mainly as it allows for commenting. Each ceremony type has a different set of configuration fields.

### Root ceremony

- `ceremony-type`: string describing the ceremony type, `root`.
- `pkcs11`: object containing PKCS#11 related fields.
    | Field | Description |
    | --- | --- |
    | `module` | Path to the PKCS#11 module to use to communicate with a HSM. |
    | `key-slot` | Specifies which HSM object slot the generated signing key should be stored in. |
    | `key-label` | Specifies the HSM object label for the generated signing key. |
- `key`: object containing key generation related fields.
    | Field | Description |
    | --- | --- |
    | `key-type` | Specifies the type of key to be generated, either `rsa` or `ecdsa`. If `rsa` the generated key will have an exponent of 65537 and a modulus length specified by `rsa-mod-length`. If `ecdsa` the curve is specified by `ecdsa-curve`. |
    | `ecdsa-curve` | Specifies the ECDSA curve to use when generating key, either `P-224`, `P-256`, `P-384`, or `P-521`. |
    | `rsa-mod-length` | Specifies the length of the RSA modulus, either `2048` or `4096`.
- `outputs`: object containing paths to write outputs.
    | Field | Description |
    | --- | --- |
    | `public-key-path` | Path to store generated PEM public key. |
    | `certificate-path` | Path to store signed PEM certificate. |
- `certificate-profile`: object containing profile for certificate to generate. Fields are documented [below](#Certificate-profile-format).

Example:

```yaml
ceremony-type: root
pkcs11:
    module: /usr/lib/opensc-pkcs11.so
    key-slot: 0
    key-label: root signing key
key:
    type: ecdsa
    ecdsa-curve: P-384
outputs:
    public-key-path: /home/user/root-signing-pub.pem
    certificate-path: /home/user/root-cert.pem
certificate-profile:
    signature-algorithm: ECDSAWithSHA384
    common-name: CA intermediate
    organization: good guys
    country: US
    not-before: 2020-01-01 12:00:00
    not-after: 2040-01-01 12:00:00
    key-usages:
        - Cert Sign
        - CRL Sign
```

This config generates a ECDSA P-384 key in the HSM with the object label `root signing key` and uses this key to sign a self-signed certificate. The public key for the key generated is written to `/home/user/root-signing-pub.pem` and the certificate is written to `/home/user/root-cert.pem`.

### Intermediate ceremony

- `ceremony-type`: string describing the ceremony type, `intermediate`.
- `pkcs11`: object containing PKCS#11 related fields.
    | Field | Description |
    | --- | --- |
    | `module` | Path to the PKCS#11 module to use to communicate with a HSM. |
    | `key-slot` | Specifies which HSM object slot the signing key is in. |
    | `key-label` | Specifies the HSM object label for the signing key. |
    | `key-id` | Specifies the HSM object ID for the signing key. |
- `inputs`: object containing paths for inputs
    | Field | Description |
    | --- | --- |
    | `public-key-path` | Path to PEM subject public key for certificate. |
    | `issuer-path` | Path to PEM issuer certificate. |
- `outputs`: object containing paths to write outputs.
    | Field | Description |
    | --- | --- |
    | `certificate-path` | Path to store signed PEM certificate. |
- `certificate-profile`: object containing profile for certificate to generate. Fields are documented [below](#Certificate-profile-format).

Example:

```yaml
ceremony-type: intermediate
pkcs11:
    module: /usr/lib/opensc-pkcs11.so
    key-slot: 0
    key-label: root signing key
    key-id: ffff
inputs:
    public-key-path: /home/user/intermediate-signing-pub.pem
    issuer-path: /home/user/root-cert.pem
outputs:
    certificate-path: /home/user/intermediate-cert.pem
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
    key-usages:
        - Digital Signature
        - Cert Sign
        - CRL Sign
```

This config generates an intermediate certificate signed by a key in the HSM, identified by the object label `root signing key` and the object ID `ffff`. The subject key used is taken from `/home/user/intermediate-signing-pub.pem` and the issuer is `/home/user/root-cert.pem`, the resulting certificate is written to `/home/user/intermediate-cert.pem`.

### Key ceremony

- `ceremony-type`: string describing the ceremony type, `key`.
- `pkcs11`: object containing PKCS#11 related fields.
    | Field | Description |
    | --- | --- |
    | `module` | Path to the PKCS#11 module to use to communicate with a HSM. |
    | `key-slot` | Specifies which HSM object slot the generated signing key should be stored in. |
    | `key-label` | Specifies the HSM object label for the generated signing key. |
- `key`: object containing key generation related fields.
    | Field | Description |
    | --- | --- |
    | `key-type` | Specifies the type of key to be generated, either `rsa` or `ecdsa`. If `rsa` the generated key will have an exponent of 65537 and a modulus length specified by `rsa-mod-length`. If `ecdsa` the curve is specified by `ecdsa-curve`. |
    | `ecdsa-curve` | Specifies the ECDSA curve to use when generating key, either `P-224`, `P-256`, `P-384`, or `P-521`. |
    | `rsa-mod-length` | Specifies the length of the RSA modulus, either `2048` or `4096`.
- `outputs`: object containing paths to write outputs.
    | Field | Description |
    | --- | --- |
    | `public-key-path` | Path to store generated PEM public key. |

Example:

```yaml
ceremony-type: key
pkcs11:
    module: /usr/lib/opensc-pkcs11.so
    key-slot: 0
    key-label: intermediate signing key
key:
    key-type: ecdsa
    ecdsa-curve: P-384
outputs:
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
| `key-usages` | Specifies list of key usage bits should be set, list can contain `Digital Signature`, `CRL Sign`, and `Cert Sign` |
