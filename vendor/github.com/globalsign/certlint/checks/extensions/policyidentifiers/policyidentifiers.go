package policyidentifiers

import (
	"crypto/x509/pkix"
	"encoding/asn1"

	"github.com/globalsign/certlint/certdata"
	"github.com/globalsign/certlint/checks"
	"github.com/globalsign/certlint/errors"
)

const checkName = "PolicyIdentifiers Extension Check"

var extensionOid = asn1.ObjectIdentifier{2, 5, 29, 32}

func init() {
	checks.RegisterExtensionCheck(checkName, extensionOid, nil, Check)
}

// Check performs a strict verification on the extension according to the standard(s)
//
// Section 7.1.2.3 (a) of the Baseline Requirements states:
//
//  This extension MUST be present and SHOULD NOT be marked critical.
//
//  A Policy Identifier, defined by the issuing CA, that indicates a
//  Certificate Policy asserting the issuing CA's adherence to and compliance
//  with these Requirements.
func Check(ex pkix.Extension, d *certdata.Data) *errors.Errors {
	var e = errors.New(nil)

	// certificatePolicies SHOULD NOT be marked critical
	if ex.Critical {
		e.Err("PolicyIdentifiers extension set critical")
	}

	// A policy must be defined
	if len(d.Cert.PolicyIdentifiers) == 0 {
		e.Err("PolicyIdentifiers not present")
	}

	return e
}
