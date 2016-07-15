We make a copy of crypto/x509 that vendors encoding/asn1, specifically to allow
CSRs with empty integers in their encodings, so that we can provide a migration
window for people whose clients exhibit the empty integer bug:
http://github.com/letsencrypt/boulder/issues/1514#issuecomment-188522792

We specifically don't vendor this library because otherwise it would replace the
standard x509 package for all types. Because types from the x509 package
interact with types in other standard packages, this would wind up requiring us
to vendor more packages from the standard library than we want to. Instead we
copy this library under a different name and use it only for CertificateRequest,
ParseCertificateRequest, and the hash types used by those.
