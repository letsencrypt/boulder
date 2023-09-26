package lints

import (
	"time"

	"github.com/zmap/zcrypto/encoding/asn1"
	"github.com/zmap/zcrypto/x509/pkix"
	"github.com/zmap/zlint/v3/lint"
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

// ReadASN1BooleanWithTag reports whether the incoming bytes from a decoded
// ASN.1 Tag are a valid X.690 BOOLEAN. The caller is responsible for parsing
// the ASN.1 Tag.
func ReadASN1BooleanWithTag(parsedByes []byte) bool {
	// X.690 (07/2002) section 8.2 states that a boolean will have length of 1
	// and value true will have contents FF.
	// https://www.itu.int/rec/T-REC-X.690-200207-S/en
	return (len(parsedByes) == 1 && parsedByes[0] == 0xFF)
}
