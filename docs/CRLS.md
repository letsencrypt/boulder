# CRLs

For each issuer certificate, Boulder generates several sharded CRLs.
The responsibility is shared across these components:

 - crl-updater
 - ca
 - crl-storer
 - sa

The crl-updater starts the process: for each shard of each issuer,
it requests revoked certificate information from the SA. It sends
that information to the CA for signing, and received back a signed
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

Certificates are assigned to shards two ways: temporally and explicitly.
Temporal shard assignment places certificates into shards based on their
notAfter. Explicit shard assignment places certificates into shards based
on the (random) low bytes of their serial numbers. All certificates
implicitly have a temporal shard. Only certificates with the
CRLDistributionPoints extension are considered to have an explicit shard.

As of Jan 2025, we are planning to start assigning explicit shards at
issuance time and then, after a transition period, turn off temporal sharding.

## Storage

When a certificate is revoked, its status in the `certificateStatus` table is
always updated. If that certificate has an explicit shard, an entry in the
`revokedCertificates` table is also added or updated. Note: the certificateStatus
table has an entry for every certificate, even unrevoked ones. The
`revokedCertificates` table only has entries for revoked certificates.

The SA exposes the two different types of recordkeeping in two different ways:
`GetRevokedCerts` returns revoked certificates whose NotAfter dates fall
within a requested range. This is used for temporal sharding.
`GetRevokedCertsByShard` returns revoked certificates whose `shardIdx` matches
the requested shard.

For each shard, the crl-storer queries both methods. Typically a certificate
will have a different temporal shard than its explicit shard, so for a
transition period, revoked certs may show up in two different CRL shards.
A fraction of certificates will have the same temporal shard as their explicit
shard. To avoid including the same serial twice in the same sharded CRL, the
crl-updater de-duplicates by serial number.

## Enabling explicit sharding

Explicit sharding is enabled at the CA by configuring each issuer with a number
of CRL shards. This number must be the same across all issuers and must match
the number of shards configured on the crl-updater.

Once we've turned on explicit sharding, we can turn it back off. However, for
the certificates we've already issued, we are still committed to serving their
revocations in the CRL hosted at the URL embedded in those certificates.
Fortunately, all of the revocation and storage elements that rely on explicit
sharding are gated by the contents of the certificate being revoked (specifically,
the presence of CRLDistributionPoints). So even if we turn off explicit sharding
for new certificates, we will still do the right thing at revocation time and
CRL generation time for any already existing certificates that have a
CRLDistributionPoints extension.
