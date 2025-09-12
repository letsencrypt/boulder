# CRLs

For each issuer certificate, Boulder generates several sharded CRLs.
The responsibility is shared across these components:

- crl-updater
- sa
- ca
- crl-storer

The crl-updater starts the process: for each shard of each issuer,
it requests revoked certificate information from the SA. It sends
that information to the CA for signing, and receives back a signed
CRL. It sends the signed CRL to the crl-storer for upload to an
S3-compatible data store.

The crl-storer uploads the CRLs to the filename `<issuerID>/<shard>.crl`,
where `issuerID` is an integer that uniquely identifies the Subject of
the issuer certificate (based on hashing the Subject's encoded bytes).

There's one more component that's not in this repository: an HTTP server
to serve objects from the S3-compatible data store. For Let's Encrypt, this
role is served by a CDN. Note that the CA must be carefully configured so
that the CRLBaseURL for each issuer matches the publicly accessible URL
where that issuer's CRLs will be served.

## Shard assignment

Certificates are assigned to shards explicitly at issuance time, with the
selected shard baked into the certificate as part of its CRLDistributionPoints
extension. The shard is selected based on taking the (random) low bytes of the
serial number modulo the number of shards produced by that certificate's issuer.

## Storage

When a certificate is revoked, the new status is written to both the
`certificateStatus` table and the `revokedCertificates` table. The former
contains an entry for every certificate, explicitly recording that newly-issued
certificates are not revoked. The latter is less explicit but more scalable,
containing rows only for certificates which have been revoked.

The SA exposes the two different types of recordkeeping in two different ways:
`GetRevokedCerts` returns revoked certificates whose NotAfter dates fall within
a requested range. `GetRevokedCertsByShard` returns revoked certificates whose
`shardIdx` matches the requested shard. The crl-updater uses only the latter
method, and the former will be removed in the future.
