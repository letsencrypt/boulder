package extkeyusage

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"

	"github.com/globalsign/certlint/certdata"
	"github.com/globalsign/certlint/checks"
	"github.com/globalsign/certlint/errors"
)

const checkName = "ExtKeyUsage Extension Check"

var extensionOid = asn1.ObjectIdentifier{2, 5, 29, 37}

func init() {
	checks.RegisterExtensionCheck(checkName, extensionOid, nil, Check)
}

// Check performs a strict verification on the extension according to the standard(s)
//
// https://tools.ietf.org/html/rfc5280#section-4.2.1.12
//
// This extension MAY, at the option of the certificate issuer, be either critical or non-critical.
//
func Check(ex pkix.Extension, d *certdata.Data) *errors.Errors {
	var e = errors.New(nil)

	// RFC: In general, this extension will appear only in end entity certificates.
	if d.Cert.IsCA {
		e.Err("In general ExtKeyUsage will appear only in end entity certificates")
	}

	// RFC: Conforming CAs	SHOULD NOT mark this extension as critical if the
	// anyExtendedKeyUsage KeyPurposeId is present.
	if ex.Critical {
		for _, ku := range d.Cert.ExtKeyUsage {
			if ku == x509.ExtKeyUsageAny {
				e.Err("ExtKeyUsage extension SHOULD NOT be critical if anyExtendedKeyUsage is present")
				break
			}
		}
	}

	return e
}
