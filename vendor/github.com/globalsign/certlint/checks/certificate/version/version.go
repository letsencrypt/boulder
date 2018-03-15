package version

import (
	"github.com/globalsign/certlint/certdata"
	"github.com/globalsign/certlint/checks"
	"github.com/globalsign/certlint/errors"
)

const checkName = "Certificate Version Check"

func init() {
	checks.RegisterCertificateCheck(checkName, nil, Check)
}

// Check performs a strict verification on the extension according to the standard(s)
func Check(d *certdata.Data) *errors.Errors {
	var e = errors.New(nil)

	if d.Cert.Version != 3 {
		e.Err("Certificate is not V3 (%d)", d.Cert.Version)
		return e
	}

	return nil
}
