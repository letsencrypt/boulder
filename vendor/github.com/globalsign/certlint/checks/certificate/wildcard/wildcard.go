package wildcard

import (
	"strings"

	"github.com/globalsign/certlint/certdata"
	"github.com/globalsign/certlint/checks"
	"github.com/globalsign/certlint/errors"
)

const checkName = "Wildcard(s) Check"

func init() {
	checks.RegisterCertificateCheck(checkName, nil, Check)
}

// Check performs a strict verification on the extension according to the standard(s)
func Check(d *certdata.Data) *errors.Errors {
	var e = errors.New(nil)

	switch d.Type {
	case "EV":
		if strings.LastIndex(d.Cert.Subject.CommonName, "*") > -1 {
			e.Err("Certificate should not contain a wildcard")
		}
		for _, n := range d.Cert.DNSNames {
			if strings.LastIndex(n, "*") > -1 {
				e.Err("Certificate subjectAltName '%s' should not contain a wildcard", n)
			}
		}
	case "DV", "OV":
		if strings.LastIndex(d.Cert.Subject.CommonName, "*") > 0 {
			e.Err("Certificate wildcard is only allowed as prefix")
		}
		for _, n := range d.Cert.DNSNames {
			if strings.LastIndex(n, "*") > 0 {
				e.Err("Certificate subjectAltName '%s' wildcard is only allowed as prefix", n)
			}
		}
	}

	return e
}
