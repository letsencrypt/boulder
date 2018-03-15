package revocation

import (
	"net/url"

	"github.com/globalsign/certlint/certdata"
	"github.com/globalsign/certlint/checks"
	"github.com/globalsign/certlint/errors"
)

const checkName = "Certificate Revocation Information Check"

func init() {
	checks.RegisterCertificateCheck(checkName, nil, Check)
}

// Check performs a strict verification on the extension according to the standard(s)
func Check(d *certdata.Data) *errors.Errors {
	var e = errors.New(nil)

	// OCSP signing certificates should not contain an OCSP server
	if d.Type == "OCSP" {
		if len(d.Cert.OCSPServer) > 0 {
			e.Warning("OCSP signing certificate contains an OCSP server")
		}

		// no extra checks needed
		return e
	}

	// Self signed CA certificates should not contain any revocation sources
	if d.Type == "CA" && d.Cert.CheckSignatureFrom(d.Cert) == nil {
		if len(d.Cert.CRLDistributionPoints) != 0 && len(d.Cert.OCSPServer) != 0 {
			e.Warning("Self signed CA certificates should not contain any revocation sources")
		}
		return e
	}

	if len(d.Cert.CRLDistributionPoints) == 0 && len(d.Cert.OCSPServer) == 0 {
		e.Err("Certificate contains no CRL or OCSP server")
		return e
	}

	// Check CRL information
	for _, crl := range d.Cert.CRLDistributionPoints {
		l, err := url.Parse(crl)
		if err != nil {
			e.Err("Certificate contains an invalid CRL (%s)", crl)
		} else if l.Scheme != "http" {
			e.Err("Certificate contains a CRL with an non-preferred scheme (%s)", l.Scheme)
		}
	}

	// Check OCSP information
	for _, server := range d.Cert.OCSPServer {
		s, err := url.Parse(server)
		if err != nil {
			e.Err("Certificate contains an invalid OCSP server (%s)", s)
		} else if s.Scheme != "http" {
			e.Err("Certificate contains a OCSP server with an non-preferred scheme (%s)", s.Scheme)
		}
	}

	return e
}
