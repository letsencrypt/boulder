package ocspnocheck

import (
	"crypto/x509/pkix"
	"encoding/asn1"

	"github.com/globalsign/certlint/certdata"
	"github.com/globalsign/certlint/checks"
	"github.com/globalsign/certlint/errors"
)

const checkName = "OCSP Nocheck Extension Check"

var extensionOid = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 5}

func init() {
	checks.RegisterExtensionCheck(checkName, extensionOid, nil, Check)
}

// Check performs a strict verification on the extension according to the standard(s)
func Check(ex pkix.Extension, d *certdata.Data) *errors.Errors {
	var e = errors.New(nil)

	if d.Type != "OCSP" {
		e.Err("OCSP Nocheck extension set in non OCSP signing certificate")
	}

	if ex.Critical {
		e.Err("OCSP Nocheck Capabilities extension set critical")
	}

	return e
}
