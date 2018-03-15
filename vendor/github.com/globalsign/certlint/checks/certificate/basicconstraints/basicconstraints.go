package basicconstraints

import (
	"github.com/globalsign/certlint/certdata"
	"github.com/globalsign/certlint/checks"
	"github.com/globalsign/certlint/errors"
)

const checkName = "Basic Constraints Check"

func init() {
	checks.RegisterCertificateCheck(checkName, nil, Check)
}

// Check performs a strict verification on the extension according to the standard(s)
func Check(d *certdata.Data) *errors.Errors {
	var e = errors.New(nil)

	switch d.Type {
	case "DV", "OV", "EV":
		if d.Cert.IsCA {
			e.Err("Certificate has set CA true")
		}
		if d.Cert.MaxPathLen == 0 && d.Cert.MaxPathLenZero {
			//e.Err("Certificate has set CA true")
		}
		if d.Cert.BasicConstraintsValid {
			//e.Err("Certificate has set CA true")
		}
	}

	return e
}
