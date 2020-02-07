# `ceremony`

`ceremony` is a tool designed for Certificate Authority specific key and certificate ceremonies. The main design principle is that unlike most ceremony tooling there is a single user input, a configuration file, which is required to complete a root, intermediate, or key ceremony. The goal is to make ceremonies as simple as possible and allow for simple verification of a single file, instead of verification of a large number of independent commands.

`ceremony` operates in one of three modes
* `root` - generates a signing key on HSM and creates a self-signed root certificate that uses the generated key, outputting a PEM public key, and a PEM certificate
* `intermediate` - creates a intermediate certificate and signs it using a signing key already on a HSM, outputting a PEM certificate
* `key` - generates a signing key on HSM, outputting a PEM public key

## Configuration format

`ceremony` uses YAML for its configuration file.

| Field | Ceremony Type | Description |
| `pkcs11-module` | All | Path to the PKCS#11 module to use to communicate with a HSM. |
| `ceremony-type` |  |  |
| `key-slot` |  |  |
| `key-label` |  |  |
| `key-id` |  |  |
| `key-type` |  |  |
| `ecdsa-curve` |  |  |
| `public-key-path` |  |  |
| `certificate-path` |  |  |
| `issuer-path` |  |  |
| `certificate-profile` |  |  |

### Example configs

#### Root ceremony

#### Intermediate ceremony

#### Key ceremony

### Certificate profile format


