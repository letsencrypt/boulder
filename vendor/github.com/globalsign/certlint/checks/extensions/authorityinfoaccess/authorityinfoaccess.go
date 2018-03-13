package authorityinfoaccess

import (
	"crypto/x509/pkix"
	"encoding/asn1"

	"github.com/globalsign/certlint/certdata"
	"github.com/globalsign/certlint/checks"
	"github.com/globalsign/certlint/errors"
)

const checkName = "AuthorityInfoAccess Extension Check"

var extensionOid = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1}

func init() {
	checks.RegisterExtensionCheck(checkName, extensionOid, nil, Check)
}

// Check performs a strict verification on the extension according to the standard(s)
// TODO: Add more checks https://golang.org/src/github.com/globalsign/certlint/certdata/x509.go?s=15439:18344#L1157
func Check(ex pkix.Extension, d *certdata.Data) *errors.Errors {
	var e = errors.New(nil)

	if ex.Critical {
		e.Err("AuthorityInfoAccess extension set critical")
	}

	return e
}
