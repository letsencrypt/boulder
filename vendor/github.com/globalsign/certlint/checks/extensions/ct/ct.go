package ct

import (
	"crypto/x509/pkix"
	"encoding/asn1"

	"github.com/globalsign/certlint/certdata"
	"github.com/globalsign/certlint/checks"
	"github.com/globalsign/certlint/errors"
)

const checkName = "Certificate Transparency Extension Check"

var extensionOid = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}

func init() {
	checks.RegisterExtensionCheck(checkName, extensionOid, nil, Check)
}

// Check performs a strict verification on the extension according to the standard(s)
//
// https://tools.ietf.org/html/rfc6962
//
// TODO: Check it's present in EV certificates issued after xxx
func Check(ex pkix.Extension, d *certdata.Data) *errors.Errors {
	var e = errors.New(nil)

	if ex.Critical {
		e.Err("Certificate Transparency extension set critical")
	}

	return e
}
