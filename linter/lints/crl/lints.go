package crl

import (
	"time"

	"github.com/zmap/zlint/v3"
	"github.com/zmap/zlint/v3/lint"

	crl_x509 "github.com/letsencrypt/boulder/crl/x509"
)

type crlLint func(*crl_x509.RevocationList) *lint.LintResult

// registry is the collection of all known CRL lints. It is populated by this
// file's init(), and should not be touched by anything else on pain of races.
var registry map[string]crlLint

func init() {
	// NOTE TO DEVS: you MUST add your new lint function to this list or it
	// WILL NOT be run.
	registry = map[string]crlLint{
		"isVersion2":    isVersion2,
		"hasNextUpdate": hasNextUpdate,
		"hasNumber":     hasNumber,
		"hasAKI":        hasAKI,
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

// isVersion2 checks RFC 5280, Section 5:
// CRLs MUST be version 2 CRLs
func isVersion2(crl *crl_x509.RevocationList) *lint.LintResult {
	// TODO: Figure out how best to check this, since Version isn't surfaced.
	return &lint.LintResult{Status: lint.NA}
}

// hasNextUpdate checks RFC 5280, Section 5:
// CRLs MUST... include the date by which the next CRL will be issued in the
// nextUpdate field
func hasNextUpdate(crl *crl_x509.RevocationList) *lint.LintResult {
	if crl.NextUpdate.IsZero() {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "CRLs MUST include the date by which the next CRL will be issued in the nextUpdate field",
		}
	}
	return &lint.LintResult{Status: lint.Pass}
}

// hasNumber checks RFC 5280, Section 5:
// CRLs MUST... include the CRL number extension
func hasNumber(crl *crl_x509.RevocationList) *lint.LintResult {
	if crl.Number == nil {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "CRLs MUST include the CRL number extension",
		}
	}
	return &lint.LintResult{Status: lint.Pass}
}

// hasAKI checks RFC 5280, Section 5:
// CRLs MUST... include the authority key identifier extension
func hasAKI(crl *crl_x509.RevocationList) *lint.LintResult {
	if len(crl.AuthorityKeyId) == 0 {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "CRLs MUST include the authority key identifier extension",
		}
	}
	return &lint.LintResult{Status: lint.Pass}
}
