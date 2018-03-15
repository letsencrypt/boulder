package publicsuffix

import (
	"fmt"
	"strings"

	"github.com/globalsign/certlint/certdata"
	"github.com/globalsign/certlint/checks"
	"github.com/globalsign/certlint/errors"

	psl "golang.org/x/net/publicsuffix"
)

const checkName = "Public Suffix (xTLD) Check"

func init() {
	filter := &checks.Filter{
		Type: []string{"DV", "OV", "IV", "EV"},
	}
	checks.RegisterCertificateCheck(checkName, filter, Check)
}

// Check performs a strict verification on the extension according to the standard(s)
func Check(d *certdata.Data) *errors.Errors {
	var e = errors.New(nil)

	if len(d.Cert.Subject.CommonName) > 0 {
		suffix, icann := psl.PublicSuffix(strings.ToLower(d.Cert.Subject.CommonName))
		if fmt.Sprintf("*.%s", suffix) == d.Cert.Subject.CommonName || suffix == d.Cert.Subject.CommonName {
			// if there is a dot on the suffix, it must be on the psl
			if icann || strings.Count(suffix, ".") > 0 {
				e.Err("Certificate CommonName %q equals %q from the public suffix list", d.Cert.Subject.CommonName, suffix)
			}
		}
	}

	for _, n := range d.Cert.DNSNames {
		suffix, icann := psl.PublicSuffix(strings.ToLower(n))
		if fmt.Sprintf("*.%s", suffix) == n || suffix == n {
			// if there is a dot on the suffix, it must be on the psl
			if icann || strings.Count(suffix, ".") > 0 {
				e.Err("Certificate subjectAltName %q equals %q from the public suffix list", n, suffix)
			}
		}
	}

	return e
}
