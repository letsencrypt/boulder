package smimecapabilities

import (
	"crypto/x509/pkix"
	"encoding/asn1"

	"github.com/globalsign/certlint/certdata"
	"github.com/globalsign/certlint/checks"
	"github.com/globalsign/certlint/errors"
)

const checkName = "S/MIME Capabilities Extension Check"

var extensionOid = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 15}

func init() {
	checks.RegisterExtensionCheck(checkName, extensionOid, nil, Check)
}

// Check performs a strict verification on the extension according to the standard(s)
func Check(ex pkix.Extension, d *certdata.Data) *errors.Errors {
	var e = errors.New(nil)

	if ex.Critical {
		e.Err("S/MIME Capabilities extension set critical")
	}

	return e
}
