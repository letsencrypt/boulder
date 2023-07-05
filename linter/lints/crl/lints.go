package crl

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"time"

	"github.com/zmap/zlint/v3"
	"github.com/zmap/zlint/v3/lint"

	"github.com/letsencrypt/boulder/crl/crl_x509"
)

const (
	utcTimeFormat         = "YYMMDDHHMMSSZ"
	generalizedTimeFormat = "YYYYMMDDHHMMSSZ"
)

type crlLint func(*crl_x509.RevocationList) *lint.LintResult

// registry is the collection of all known CRL lints. It is populated by this
// file's init(), and should not be touched by anything else on pain of races.
var registry map[string]crlLint

func init() {
	// NOTE TO DEVS: you MUST add your new lint function to this list or it
	// WILL NOT be run.
	registry = map[string]crlLint{
		"hasIssuerName":                  hasIssuerName,
		"hasNextUpdate":                  hasNextUpdate,
		"noEmptyRevokedCertificatesList": noEmptyRevokedCertificatesList,
		"hasAKI":                         hasAKI,
		"hasNumber":                      hasNumber,
		"isNotDelta":                     isNotDelta,
		"checkIDP":                       checkIDP,
		"hasNoFreshest":                  hasNoFreshest,
		"hasNoAIA":                       hasNoAIA,
		"noZeroReasonCodes":              noZeroReasonCodes,
		"hasNoCertIssuers":               hasNoCertIssuers,
		"hasAcceptableValidity":          hasAcceptableValidity,
		"noCriticalReasons":              noCriticalReasons,
		"noCertificateHolds":             noCertificateHolds,
		"hasMozReasonCodes":              hasMozReasonCodes,
		"hasValidTimestamps":             hasValidTimestamps,
	}
}

// getExtWithOID is a helper for several lints in this file. It returns the
// extension with the given OID if it exists, or nil otherwise.
func getExtWithOID(exts []pkix.Extension, oid asn1.ObjectIdentifier) *pkix.Extension {
	for _, ext := range exts {
		if ext.Id.Equal(oid) {
			return &ext
		}
	}
	return nil
}

// LintCRL examines the given lint CRL, runs it through all of our checks, and
// returns a list of all failures
func LintCRL(lintCRL *crl_x509.RevocationList) *zlint.ResultSet {
	rset := zlint.ResultSet{
		Version:   0,
		Timestamp: time.Now().UnixNano(),
		Results:   make(map[string]*lint.LintResult),
	}

	type namedResult struct {
		Name   string
		Result *lint.LintResult
	}
	resChan := make(chan namedResult, len(registry))

	for name, callable := range registry {
		go func(name string, callable crlLint) {
			resChan <- namedResult{name, callable(lintCRL)}
		}(name, callable)
	}

	for i := 0; i < len(registry); i++ {
		res := <-resChan
		switch res.Result.Status {
		case lint.Notice:
			rset.NoticesPresent = true
		case lint.Warn:
			rset.WarningsPresent = true
		case lint.Error:
			rset.ErrorsPresent = true
		case lint.Fatal:
			rset.FatalsPresent = true
		}
		rset.Results[res.Name] = res.Result
	}

	return &rset
}

// hasAcceptableValidity checks Baseline Requirements, Section 4.9.7:
// The value of the nextUpdate field MUST NOT be more than ten days beyond the
// value of the thisUpdate field.
func hasAcceptableValidity(crl *crl_x509.RevocationList) *lint.LintResult {
	validity := crl.NextUpdate.Sub(crl.ThisUpdate)
	if validity <= 0 {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "CRL has NextUpdate at or before ThisUpdate",
		}
	} else if validity > 10*24*time.Hour {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "CRL has validity period greater than ten days",
		}
	}
	return &lint.LintResult{Status: lint.Pass}
}

// noZeroReasonCodes checks Baseline Requirements, Section 7.2.2.1:
// The CRLReason indicated MUST NOT be unspecified (0). If the reason for
// revocation is unspecified, CAs MUST omit reasonCode entry extension, if
// allowed by the previous requirements.
// By extension, it therefore also checks RFC 5280, Section 5.3.1:
// The reason code CRL entry extension SHOULD be absent instead of using the
// unspecified (0) reasonCode value.
func noZeroReasonCodes(crl *crl_x509.RevocationList) *lint.LintResult {
	for _, entry := range crl.RevokedCertificates {
		if entry.ReasonCode != nil && *entry.ReasonCode == 0 {
			return &lint.LintResult{
				Status:  lint.Error,
				Details: "CRL entries MUST NOT contain the unspecified (0) reason code",
			}
		}
	}
	return &lint.LintResult{Status: lint.Pass}
}

// noCrticialReasons checks Baseline Requirements, Section 7.2.2.1:
// If present, [the reasonCode] extension MUST NOT be marked critical.
func noCriticalReasons(crl *crl_x509.RevocationList) *lint.LintResult {
	reasonCodeOID := asn1.ObjectIdentifier{2, 5, 29, 21} // id-ce-reasonCode
	for _, rc := range crl.RevokedCertificates {
		for _, ext := range rc.Extensions {
			if ext.Id.Equal(reasonCodeOID) && ext.Critical {
				return &lint.LintResult{
					Status:  lint.Error,
					Details: "CRL entry reasonCodes MUST NOT be critical",
				}
			}
		}
	}
	return &lint.LintResult{Status: lint.Pass}
}

// noCertificateHolds checks Baseline Requirements, Section 7.2.2.1:
// The CRLReason MUST NOT be certificateHold (6).
func noCertificateHolds(crl *crl_x509.RevocationList) *lint.LintResult {
	for _, entry := range crl.RevokedCertificates {
		if entry.ReasonCode != nil && *entry.ReasonCode == 6 {
			return &lint.LintResult{
				Status:  lint.Error,
				Details: "CRL entries MUST NOT use the certificateHold (6) reason code",
			}
		}
	}
	return &lint.LintResult{Status: lint.Pass}
}

// hasMozReasonCodes checks MRSP v2.8 Section 6.1.1:
// When the CRLReason code is not one of the following, then the reasonCode extension MUST NOT be provided:
// - keyCompromise (RFC 5280 CRLReason #1);
// - privilegeWithdrawn (RFC 5280 CRLReason #9);
// - cessationOfOperation (RFC 5280 CRLReason #5);
// - affiliationChanged (RFC 5280 CRLReason #3); or
// - superseded (RFC 5280 CRLReason #4).
func hasMozReasonCodes(crl *crl_x509.RevocationList) *lint.LintResult {
	for _, rc := range crl.RevokedCertificates {
		if rc.ReasonCode == nil {
			continue
		}
		switch *rc.ReasonCode {
		case 1: // keyCompromise
		case 3: // affiliationChanged
		case 4: // superseded
		case 5: // cessationOfOperation
		case 9: // privilegeWithdrawn
			continue
		default:
			return &lint.LintResult{
				Status:  lint.Error,
				Details: "CRLs MUST NOT include reasonCodes other than 1, 3, 4, 5, and 9",
			}
		}
	}
	return &lint.LintResult{Status: lint.Pass}
}
