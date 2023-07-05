package rfc

import (
	"errors"
	"fmt"
	"time"

	"github.com/letsencrypt/boulder/crl/crl_x509"
	"github.com/zmap/zlint/v3/lint"
	"golang.org/x/crypto/cryptobyte"
)

// hasValidTimestamps validates encoding of all CRL timestamp values as
// specified in section 4.1.2.5 of RFC5280. Timestamp values MUST be encoded as
// either UTCTime or a GeneralizedTime.
//
// UTCTime values MUST be expressed in Greenwich Mean Time (Zulu) and MUST
// include seconds (i.e., times are YYMMDDHHMMSSZ), even where the number of
// seconds is zero. See:
// https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1.2.5.1
//
// GeneralizedTime values MUST be expressed in Greenwich Mean Time (Zulu) and
// MUST include seconds (i.e., times are YYYYMMDDHHMMSSZ), even where the number
// of seconds is zero.  GeneralizedTime values MUST NOT include fractional
// seconds. See: https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1.2.5.2
//
// Conforming applications MUST encode thisUpdate, nextUpdate, and cerficate
// validity timestamps prior to 2050 as UTCTime and GeneralizedTime there-after.
// See:
//   - https://www.rfc-editor.org/rfc/rfc5280.html#section-5.1.2.4
//   - https://www.rfc-editor.org/rfc/rfc5280.html#section-5.1.2.5
//   - https://www.rfc-editor.org/rfc/rfc5280.html#section-5.1.2.6
func hasValidTimestamps(crl *crl_x509.RevocationList) *lint.LintResult {
	input := cryptobyte.String(crl.RawTBSRevocationList)
	lintFail := lint.LintResult{
		Status:  lint.Error,
		Details: "Failed to re-parse tbsCertList during linting",
	}

	// Read tbsCertList.
	var tbs cryptobyte.String
	if !input.ReadASN1(&tbs, cryptobyte_asn1.SEQUENCE) {
		return &lintFail
	}

	// Skip (optional) version.
	if !tbs.SkipOptionalASN1(cryptobyte_asn1.INTEGER) {
		return &lintFail
	}

	// Skip signature.
	if !tbs.SkipASN1(cryptobyte_asn1.SEQUENCE) {
		return &lintFail
	}

	// Skip issuer.
	if !tbs.SkipASN1(cryptobyte_asn1.SEQUENCE) {
		return &lintFail
	}

	// Read thisUpdate.
	var thisUpdate cryptobyte.String
	var thisUpdateTag cryptobyte_asn1.Tag
	if !tbs.ReadAnyASN1Element(&thisUpdate, &thisUpdateTag) {
		return &lintFail
	}

	// Lint thisUpdate.
	err := lintTimestamp(&thisUpdate, thisUpdateTag)
	if err != nil {
		return &lint.LintResult{Status: lint.Error, Details: err.Error()}
	}

	// Peek (optional) nextUpdate.
	if tbs.PeekASN1Tag(cryptobyte_asn1.UTCTime) || tbs.PeekASN1Tag(cryptobyte_asn1.GeneralizedTime) {
		// Read nextUpdate.
		var nextUpdate cryptobyte.String
		var nextUpdateTag cryptobyte_asn1.Tag
		if !tbs.ReadAnyASN1Element(&nextUpdate, &nextUpdateTag) {
			return &lintFail
		}

		// Lint nextUpdate.
		err = lintTimestamp(&nextUpdate, nextUpdateTag)
		if err != nil {
			return &lint.LintResult{Status: lint.Error, Details: err.Error()}
		}
	}

	// Peek (optional) revokedCertificates.
	if tbs.PeekASN1Tag(cryptobyte_asn1.SEQUENCE) {
		// Read sequence of revokedCertificate.
		var revokedSeq cryptobyte.String
		if !tbs.ReadASN1(&revokedSeq, cryptobyte_asn1.SEQUENCE) {
			return &lintFail
		}

		// Iterate over each revokedCertificate sequence.
		for !revokedSeq.Empty() {
			// Read revokedCertificate.
			var certSeq cryptobyte.String
			if !revokedSeq.ReadASN1Element(&certSeq, cryptobyte_asn1.SEQUENCE) {
				return &lintFail
			}

			if !certSeq.ReadASN1(&certSeq, cryptobyte_asn1.SEQUENCE) {
				return &lintFail
			}

			// Skip userCertificate (serial number).
			if !certSeq.SkipASN1(cryptobyte_asn1.INTEGER) {
				return &lintFail
			}

			// Read revocationDate.
			var revocationDate cryptobyte.String
			var revocationDateTag cryptobyte_asn1.Tag
			if !certSeq.ReadAnyASN1Element(&revocationDate, &revocationDateTag) {
				return &lintFail
			}

			// Lint revocationDate.
			err = lintTimestamp(&revocationDate, revocationDateTag)
			if err != nil {
				return &lint.LintResult{Status: lint.Error, Details: err.Error()}
			}
		}
	}
	return &lint.LintResult{Status: lint.Pass}
}

func lintTimestamp(der *cryptobyte.String, tag cryptobyte_asn1.Tag) error {
	// Preserve the original timestamp for length checking.
	derBytes := *der
	var tsBytes cryptobyte.String
	if !derBytes.ReadASN1(&tsBytes, tag) {
		return errors.New("failed to read timestamp")
	}
	tsLen := len(string(tsBytes))

	var parsedTime time.Time
	switch tag {
	case cryptobyte_asn1.UTCTime:
		// Verify that the timestamp is properly formatted.
		if tsLen != len(utcTimeFormat) {
			return fmt.Errorf("timestamps encoded using UTCTime MUST be specified in the format %q", utcTimeFormat)
		}

		if !der.ReadASN1UTCTime(&parsedTime) {
			return errors.New("failed to read timestamp encoded using UTCTime")
		}

		// Verify that the timestamp is prior to the year 2050. This should
		// really never happen.
		if parsedTime.Year() > 2049 {
			return errors.New("ReadASN1UTCTime returned a UTCTime after 2049")
		}
	case cryptobyte_asn1.GeneralizedTime:
		// Verify that the timestamp is properly formatted.
		if tsLen != len(generalizedTimeFormat) {
			return fmt.Errorf(
				"timestamps encoded using GeneralizedTime MUST be specified in the format %q", generalizedTimeFormat,
			)
		}

		if !der.ReadASN1GeneralizedTime(&parsedTime) {
			return fmt.Errorf("failed to read timestamp encoded using GeneralizedTime")
		}

		// Verify that the timestamp occurred after the year 2049.
		if parsedTime.Year() < 2050 {
			return errors.New("timestamps prior to 2050 MUST be encoded using UTCTime")
		}
	default:
		return errors.New("unsupported time format")
	}

	// Verify that the location is UTC.
	if parsedTime.Location() != time.UTC {
		return errors.New("time must be in UTC")
	}
	return nil
}
