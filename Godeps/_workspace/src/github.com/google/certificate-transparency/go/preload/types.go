package preload

import (
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/google/certificate-transparency/go"
)

type AddedCert struct {
	CertDER                    ct.ASN1Cert
	SignedCertificateTimestamp ct.SignedCertificateTimestamp
	AddedOk                    bool
	ErrorMessage               string
}
