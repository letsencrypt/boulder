package crl

import (
	"time"

	"github.com/zmap/zlint/v3"
	"github.com/zmap/zlint/v3/lint"

	"github.com/letsencrypt/boulder/crl/crl_x509"
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
