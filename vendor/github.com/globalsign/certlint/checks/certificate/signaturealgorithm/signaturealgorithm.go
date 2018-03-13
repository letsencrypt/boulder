package signaturealgorithm

import (
	"crypto/x509"
	"time"

	"github.com/globalsign/certlint/certdata"
	"github.com/globalsign/certlint/checks"
	"github.com/globalsign/certlint/errors"
)

const checkName = "Signature Algorithm Check"

func init() {
	filter := &checks.Filter{
		Type: []string{"DV", "OV", "IV", "EV"},
	}
	checks.RegisterCertificateCheck(checkName, filter, Check)
}

// Check performs a strict verification on the extension according to the standard(s)
func Check(d *certdata.Data) *errors.Errors {
	var e = errors.New(nil)

	// Check if we use SHA1 or less (MD5, MD2)
	if d.Cert.SignatureAlgorithm > x509.SHA1WithRSA &&
		d.Cert.SignatureAlgorithm != x509.DSAWithSHA1 &&
		d.Cert.SignatureAlgorithm != x509.ECDSAWithSHA1 {
		return e
	}

	if d.Cert.NotBefore.After(time.Date(2016, 1, 1, 0, 0, 0, 0, time.UTC)) {
		e.Err("Certificate is using SHA1, but is issued on/after 1 Jan 2016")
		return e
	}

	if d.Cert.NotBefore.After(time.Date(2015, 1, 16, 0, 0, 0, 0, time.UTC)) &&
		d.Cert.NotAfter.After(time.Date(2017, 1, 1, 0, 0, 0, 0, time.UTC)) {
		e.Err("Certificate is using SHA1, but is still valid on/after 1 Jan 2017")
		return e
	}

	return nil
}
