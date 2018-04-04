package ocspmuststaple

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"

	"github.com/globalsign/certlint/certdata"
	"github.com/globalsign/certlint/checks"
	"github.com/globalsign/certlint/errors"
)

const (
	checkName   = "OCSP Must Staple Extension Check"
	certTypeErr = "OCSP Must Staple extension set in non end-entity/issuer certificate"
	critExtErr  = "OCSP Must Staple extension set critical"
)

var (
	// RFC 7633 OID of the OCSP Must Staple TLS Extension Feature
	extensionOid = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 24}
	// Expected extension value (DER encoded ASN.1 bytestring)
	expectedExtensionValue = []uint8{0x30, 0x3, 0x2, 0x1, 0x5}
	extValueErr            = fmt.Sprintf(
		"OCSP Must Staple extension had incorrect value. "+
			"Should be ASN.1 DER %#v", expectedExtensionValue)
)

// RFC 7633 only defines this extension for PKIX end-entity certificates,
// certificate signing requests, and certificate signing certificates (CAs).
// We should not allow it for cert types like "OCSP", "PS", "CS", etc.
var allowedCertTypes = map[string]bool{
	"DV": true,
	"OV": true,
	"EV": true,
	"CA": true,
}

func init() {
	// Register this check for the OCSP Must Staple extension OID.
	checks.RegisterExtensionCheck(checkName, extensionOid, nil, Check)
}

// Check performs a strict verification on the extension according to the standard(s)
func Check(ex pkix.Extension, d *certdata.Data) *errors.Errors {
	var e = errors.New(nil)

	// If the cert type isn't one of the `allowedCertTypes`, return an error
	if _, allowed := allowedCertTypes[d.Type]; !allowed {
		e.Err(certTypeErr)
	}

	// Per RFC 7633 "The TLS feature extension SHOULD NOT be marked critical"
	if ex.Critical {
		e.Err(critExtErr)
	}

	// Check that the extension value is the expected slice of DER encoded ASN.1
	if bytes.Compare(ex.Value, expectedExtensionValue) != 0 {
		e.Err(extValueErr)
	}

	return e
}
