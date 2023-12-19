package lints

import (
	"net/url"
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

/*
	 IssuingDistributionPoint stores the IA5STRING value of the optional
	 distribution point, and the (implied OPTIONAL) BOOLEAN values of
	 onlyContainsUserCerts and onlyContainsCACerts.

			RFC 5280
			* Section 5.2.5
				IssuingDistributionPoint ::= SEQUENCE {
					distributionPoint          [0] DistributionPointName OPTIONAL,
					onlyContainsUserCerts      [1] BOOLEAN DEFAULT FALSE,
					onlyContainsCACerts        [2] BOOLEAN DEFAULT FALSE,
					...
				}

			* Section 4.2.1.13
				DistributionPointName ::= CHOICE {
					fullName                [0]     GeneralNames,
					... }

			* Appendix A.1, Page 128
				GeneralName ::= CHOICE {
					...
			        uniformResourceIdentifier [6]  IA5String,
					... }
*/
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
