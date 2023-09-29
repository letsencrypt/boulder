package lints

import (
	"bytes"
	"net/url"
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

type IssuingDistributionPoint struct {
	DistributionPointURI  *url.URL
	OnlyContainsUserCerts bool
	OnlyContainsCACerts   bool
}

// NewIssuingDistributionPoint is a constructor which returns an
// IssuingDistributionPoint with each field set to zero values.
func NewIssuingDistributionPoint() *IssuingDistributionPoint {
	return &IssuingDistributionPoint{}
}

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
// Unless out is nil, it stores whether an element with the tag was found in
// out, otherwise out will take the default value. It reports whether all reads
// were successful.
func ReadOptionalASN1BooleanWithTag(incoming *cryptobyte.String, out *bool, tag cryptobyte_asn1.Tag, defaultValue bool) bool {
	// ReadOptionalASN1 performs a peek and will not advance if the tag is
	// missing, meaning that incoming will retain bytes.
	var valuePresent bool
	var valueBytes cryptobyte.String
	if !incoming.ReadOptionalASN1(&valueBytes, &valuePresent, tag) {
		return false
	}
	val := defaultValue
	if valuePresent {
		boolBytes := []byte(valueBytes)
		// X.690 (07/2002) section 8.2 states that a boolean will have length of 1
		// and value true will have contents FF.
		// https://www.itu.int/rec/T-REC-X.690-200207-S/en
		if bytes.Equal(boolBytes, []byte{0xFF}) {
			val = true
		} else if bytes.Equal(boolBytes, []byte{0x00}) {
			val = false
		} else {
			// Unrecognized DER encoding of boolean!
			return false
		}
	}
	if out != nil {
		*out = val
	}

	// All reads were successful.
	return true
}
