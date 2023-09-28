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

// ReadOptionalASN1BooleanWithTag attempts to read and advance incoming to
// search for an optional DER-encoded ASN.1 element tagged with the given tag.
// Unless outExpectedTagPresent or outPresent are nil, it stores whether the tag
// was found in outExpectedTagPresent and an element with the tag was found in
// outPresent, otherwise each boolean will take the default value. It reports
// whether all reads were successful.
func ReadOptionalASN1BooleanWithTag(incoming *cryptobyte.String, outExpectedTagPresent *bool, outPresent *bool, tag cryptobyte_asn1.Tag, defaultValue bool) bool {
	if outExpectedTagPresent != nil {
		*outExpectedTagPresent = defaultValue
	}
	if outPresent != nil {
		*outPresent = defaultValue
	}
	if incoming.Empty() {
		return false
	}

	// We need to check the boolean value to determine if the tag was found. The
	// ReadOptionalASN1BooleanWithTag caller may not care about the value, but
	// here internally we do.
	tagPresent := false
	var tagBytes cryptobyte.String

	// ReadOptionalASN1 performs a peek and will not advance if the tag is
	// missing, meaning that incoming will retain bytes.
	ok := incoming.ReadOptionalASN1(&tagBytes, &tagPresent, tag)
	if !ok && !tagPresent {
		return false
	}
	if outExpectedTagPresent != nil && tagPresent {
		*outExpectedTagPresent = true
	}

	// X.690 (07/2002) section 8.2 states that a boolean will have length of 1
	// and value true will have contents FF.
	// https://www.itu.int/rec/T-REC-X.690-200207-S/en
	boolBytes := []byte(tagBytes)
	if len(boolBytes) == 1 && boolBytes[0] == 0xFF {
		if outPresent != nil {
			*outPresent = true
		}
	}

	// All reads were successful.
	return true
}
