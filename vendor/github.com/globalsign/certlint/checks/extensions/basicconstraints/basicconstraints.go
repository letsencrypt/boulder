package basicconstraints

import (
	"crypto/x509/pkix"
	"encoding/asn1"

	"github.com/globalsign/certlint/certdata"
	"github.com/globalsign/certlint/checks"
	"github.com/globalsign/certlint/errors"
)

const checkName = "BasicConstraints Extension Check"

var extensionOid = asn1.ObjectIdentifier{2, 5, 29, 19}

func init() {
	checks.RegisterExtensionCheck(checkName, extensionOid, nil, Check)
}

// Check performs a strict verification on the extension according to the standard(s)
//
// https://tools.ietf.org/html/rfc5280#section-4.2.1.9
//
func Check(ex pkix.Extension, d *certdata.Data) *errors.Errors {
	var e = errors.New(nil)

	// This extension MAY appear as a critical or non-critical extension in end
	// entity certificates.
	if d.Cert.IsCA {

		// Conforming CAs MUST include this extension in all CA certificates
		// that contain public keys used to validate digital signatures on
		// certificates and MUST mark the extension as critical in such
		// certificates.  This extension MAY appear as a critical or non-
		// critical extension in CA certificates that contain public keys used
		// exclusively for purposes other than validating digital signatures on
		// certificates.  Such CA certificates include ones that contain public
		// keys used exclusively for validating digital signatures on CRLs and
		// ones that contain key management public keys used with certificate
		// enrollment protocols.
		//
		// The CA Browser Forum BR 1.4.1 state that it should always be true for
		// CA certificates.
		if !ex.Critical {
			e.Err("BasicConstraints extension must be critical in CA certificates")
		}
	}

	return e
}
