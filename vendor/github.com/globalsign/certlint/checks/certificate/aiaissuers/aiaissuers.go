package aiaissuers

import (
	"net/url"

	"github.com/globalsign/certlint/certdata"
	"github.com/globalsign/certlint/checks"
	"github.com/globalsign/certlint/errors"
)

const checkName = "Authority Info Access Issuers Check"

func init() {
	checks.RegisterCertificateCheck(checkName, nil, Check)
}

// Check performs a strict verification on the extension according to the standard(s)
func Check(d *certdata.Data) *errors.Errors {
	var e = errors.New(nil)

	// OCSP signing certificates should not any Authority Info Access Issuers
	if d.Type == "OCSP" {
		if len(d.Cert.IssuingCertificateURL) > 0 {
			e.Warning("OCSP signing certificate contains any Authority Info Access Issuers")
		}

		// no extra checks needed
		return e
	}

	// Self signed CA certificates should not contain any AIA Issuers
	if d.Type == "CA" && d.Cert.CheckSignatureFrom(d.Cert) == nil {
		if len(d.Cert.IssuingCertificateURL) != 0 {
			e.Warning("Self signed CA certificates should not contain any Authority Info Access Issuers")
		}
		return e
	}

	// Other certificates should contain at least one Authority Info Access Issuer
	if len(d.Cert.IssuingCertificateURL) == 0 {
		e.Err("Certificate contains no Authority Info Access Issuers")
		return e
	}

	for _, icu := range d.Cert.IssuingCertificateURL {
		l, err := url.Parse(icu)
		if err != nil {
			e.Err("Certificate contains an invalid Authority Info Access Issuer URL (%s)", icu)
		}
		if l.Scheme != "http" {
			e.Warning("Certificate contains a Authority Info Access Issuer with an non-preferred scheme (%s)", l.Scheme)
		}
	}

	return e
}
