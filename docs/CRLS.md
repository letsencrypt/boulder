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

## Safety checks

Two checks guard against publishing a CRL which is missing entries, which would
appear to un-revoke certificates.

The crl-updater reads each shard's entries from a read-only SA (a database
replica). Before signing, it asks the read-write SA (the primary) for the
shard's most recent revocation via `GetLatestRevokedCertByShard`; if that entry
is missing, or the primary is unreachable, the replica is lagging and the
update fails. The `thisUpdateBackdate` setting (default 5 minutes) shifts
`thisUpdate`, and so the revocation cutoff, into the past so that ordinary
replication lag does not impact this check.

The crl-storer diffs each CRL against the previous one for the same shard. An
entry may only disappear once it has appeared on a CRL issued after its
certificate expired (RFC 5280, Section 3.3), so for each missing entry the
storer looks up the certificate's expiry (`GetSerialsMetadata`) and refuses the
upload unless it precedes the previous CRL's `thisUpdate`. The storer also
refuses CRLs whose number does not increase or whose IDP changes.

## Storage

When a certificate is revoked, the new status is written to both the
`certificateStatus` table and the `revokedCertificates` table. The former
contains an entry for every certificate, explicitly recording that newly-issued
certificates are not revoked. The latter is less explicit but more scalable,
containing rows only for certificates which have been revoked.

The SA only exposes the latter of these two mechanisms via the
`GetRevokedCertsByShard` method, which returns revoked certificates whose
`shardIdx` matches the requested shard. The `certificateStatus` table will be
removed in the near future.
