We make a copy of crypto/x509 that vendors encoding/asn1, specifically to allow
CSRs with empty integers in their encodings, so that we can provide a migration
window for people whose clients exhibit the empty integer bug:
http://github.com/letsencrypt/boulder/issues/1514#issuecomment-188522792
