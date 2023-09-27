package lints

import (
	"time"

	"github.com/zmap/zcrypto/encoding/asn1"
	"github.com/zmap/zcrypto/x509/pkix"
	"github.com/zmap/zlint/v3/lint"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

const (
	// CABF Baseline Requirements 6.3.2 Certificate operational periods:
	// For the purpose of calculations, a day is measured as 86,400 seconds.
	// Any amount of time greater than this, including fractional seconds and/or
	// leap seconds, shall represent an additional day.
	BRDay time.Duration = 86400 * time.Second

	// Declare our own Sources for use in zlint registry filtering.
	LetsEncryptCPS lint.LintSource = "LECPS"
	ChromeCTPolicy lint.LintSource = "ChromeCT"
)

var (
	CPSV33Date           = time.Date(2021, time.June, 8, 0, 0, 0, 0, time.UTC)
	MozillaPolicy281Date = time.Date(2023, time.February, 15, 0, 0, 0, 0, time.UTC)
)

// GetExtWithOID is a helper for several of our custom lints. It returns the
// extension with the given OID if it exists, or nil otherwise.
func GetExtWithOID(exts []pkix.Extension, oid asn1.ObjectIdentifier) *pkix.Extension {
	for _, ext := range exts {
		if ext.Id.Equal(oid) {
			return &ext
		}
	}
	return nil
}

// ReadOptionalASN1BooleanWithTag attempts to read the contents of an optional
// DER-encoded ASN.1 element tagged with the given tag from incoming. It reports
// whether the read was successful and the value of the boolean.
func ReadOptionalASN1BooleanWithTag(incoming *cryptobyte.String, out *bool, tag cryptobyte_asn1.Tag, defaultValue bool) bool {
	if out != nil {
		out = &defaultValue
	}

	var tagBytes cryptobyte.String
	if !incoming.ReadOptionalASN1(&tagBytes, out, tag) {
		return false
	}
	boolBytes := []byte(tagBytes)

	// X.690 (07/2002) section 8.2 states that a boolean will have length of 1
	// and value true will have contents FF.
	// https://www.itu.int/rec/T-REC-X.690-200207-S/en
	if len(boolBytes) == 1 && boolBytes[0] == 0xFF {
		if out != nil {
			*out = true
		}
		return true
	}

	return false
}
