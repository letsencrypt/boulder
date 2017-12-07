package va

import (
	"fmt"
	"strings"
	"sync"

	"github.com/letsencrypt/boulder/core"
	corepb "github.com/letsencrypt/boulder/core/proto"
	"github.com/letsencrypt/boulder/probs"
	vapb "github.com/letsencrypt/boulder/va/proto"
	"github.com/miekg/dns"
	"golang.org/x/net/context"
)

func (va *ValidationAuthorityImpl) IsCAAValid(
	ctx context.Context,
	req *vapb.IsCAAValidRequest,
) (*vapb.IsCAAValidResponse, error) {
	// We allow the presence of nil in the IsCAAValidRequest for backwards
	// compatibility for callers that haven't updated to provide a value.
	var wildcard bool
	if req.Wildcard != nil {
		wildcard = *req.Wildcard
	}
	prob := va.checkCAA(ctx, core.AcmeIdentifier{
		Type:  core.IdentifierDNS,
		Value: *req.Domain,
	}, wildcard)

	if prob != nil {
		typ := string(prob.Type)
		detail := fmt.Sprintf("While processing CAA for %s: %s", *req.Domain, prob.Detail)
		return &vapb.IsCAAValidResponse{
			Problem: &corepb.ProblemDetails{
				ProblemType: &typ,
				Detail:      &detail,
			},
		}, nil
	}
	return &vapb.IsCAAValidResponse{}, nil
}

// checkCAA performs a CAA lookup & validation for the provided identifier. If
// the wildcard argument is true then the identifier is known to be the base
// domain corresponding to a wildcard name and so the CAA validation must handle
// issueWild accordingly  If the CAA lookup & validation fail a problem is returned.
func (va *ValidationAuthorityImpl) checkCAA(
	ctx context.Context,
	identifier core.AcmeIdentifier,
	wildcard bool) *probs.ProblemDetails {
	present, valid, err := va.checkCAARecords(ctx, identifier, wildcard)
	if err != nil {
		return probs.ConnectionFailure(err.Error())
	}
	// We want to indicate which sort of CAA records we looked up in the audit
	// logs for this check
	recordType := "issue"
	if wildcard {
		recordType = "issuewild"
	}
	va.log.AuditInfo(fmt.Sprintf(
		"Checked CAA %s records for %s, [Present: %t, Valid for issuance: %t]",
		recordType,
		identifier.Value,
		present,
		valid,
	))
	if !valid {
		return probs.CAA(fmt.Sprintf("CAA record for %s prevents issuance", identifier.Value))
	}
	return nil
}

// CAASet consists of filtered CAA records
type CAASet struct {
	Issue     []*dns.CAA
	Issuewild []*dns.CAA
	Iodef     []*dns.CAA
	Unknown   []*dns.CAA
}

// returns true if any CAA records have unknown tag properties and are flagged critical.
func (caaSet CAASet) criticalUnknown() bool {
	if len(caaSet.Unknown) > 0 {
		for _, caaRecord := range caaSet.Unknown {
			// The critical flag is the bit with significance 128. However, many CAA
			// record users have misinterpreted the RFC and concluded that the bit
			// with significance 1 is the critical bit. This is sufficiently
			// widespread that that bit must reasonably be considered an alias for
			// the critical bit. The remaining bits are 0/ignore as proscribed by the
			// RFC.
			if (caaRecord.Flag & (128 | 1)) != 0 {
				return true
			}
		}
	}

	return false
}

// Filter CAA records by property
func newCAASet(CAAs []*dns.CAA) *CAASet {
	var filtered CAASet

	for _, caaRecord := range CAAs {
		switch caaRecord.Tag {
		case "issue":
			filtered.Issue = append(filtered.Issue, caaRecord)
		case "issuewild":
			filtered.Issuewild = append(filtered.Issuewild, caaRecord)
		case "iodef":
			filtered.Iodef = append(filtered.Iodef, caaRecord)
		default:
			filtered.Unknown = append(filtered.Unknown, caaRecord)
		}
	}

	return &filtered
}

type caaResult struct {
	records []*dns.CAA
	err     error
}

func parseResults(results []caaResult) (*CAASet, error) {
	// Return first result
	for _, res := range results {
		if res.err != nil {
			return nil, res.err
		}
		if len(res.records) > 0 {
			return newCAASet(res.records), nil
		}
	}
	return nil, nil
}

func (va *ValidationAuthorityImpl) parallelCAALookup(ctx context.Context, name string) []caaResult {
	labels := strings.Split(name, ".")
	results := make([]caaResult, len(labels))
	var wg sync.WaitGroup

	for i := 0; i < len(labels); i++ {
		// Start the concurrent DNS lookup.
		wg.Add(1)
		go func(name string, r *caaResult) {
			r.records, r.err = va.dnsClient.LookupCAA(ctx, name)
			wg.Done()
		}(strings.Join(labels[i:], "."), &results[i])
	}

	wg.Wait()
	return results
}

func (va *ValidationAuthorityImpl) getCAASet(ctx context.Context, hostname string) (*CAASet, error) {
	hostname = strings.TrimRight(hostname, ".")

	// See RFC 6844 "Certification Authority Processing" for pseudocode, as
	// amended by https://www.rfc-editor.org/errata/eid5065.
	// Essentially: check CAA records for the FDQN to be issued, and all
	// parent domains.
	//
	// The lookups are performed in parallel in order to avoid timing out
	// the RPC call.
	//
	// We depend on our resolver to snap CNAME and DNAME records.
	results := va.parallelCAALookup(ctx, hostname)
	return parseResults(results)
}

// checkCAARecords fetches the CAA records for the given identifier and then
// validates them. If the wildcard argument is true then the validation will
// treat the identifier as the base domain for a wildcard request, honouring any
// issueWild CAA records encountered as apppropriate. checkCAARecords returns three values:
// the first is a bool indicating whether CAA records were present. The second
// is a bool indicating whether issuance for the identifier is valid. Any errors
// encountered are returned as the third return value (or nil).
func (va *ValidationAuthorityImpl) checkCAARecords(
	ctx context.Context,
	identifier core.AcmeIdentifier,
	wildcard bool) (present, valid bool, err error) {
	hostname := strings.ToLower(identifier.Value)
	caaSet, err := va.getCAASet(ctx, hostname)
	if err != nil {
		return false, false, err
	}
	present, valid = va.validateCAASet(caaSet, wildcard)
	return present, valid, nil
}

// validateCAASet checks a provided *CAASet. When the wildcard argument is true
// this means the CAASet's issueWild records must be validated as well. This
// function returns two booleans: the first indicates whether the CAASet was
// empty, the second indicates whether the CAASet is valid for issuance to
// proceed.
func (va *ValidationAuthorityImpl) validateCAASet(caaSet *CAASet, wildcard bool) (present, valid bool) {
	if caaSet == nil {
		// No CAA records found, can issue
		va.stats.Inc("CAA.None", 1)
		return false, true
	}

	// Record stats on directives not currently processed.
	if len(caaSet.Iodef) > 0 {
		va.stats.Inc("CAA.WithIodef", 1)
	}

	if caaSet.criticalUnknown() {
		// Contains unknown critical directives.
		va.stats.Inc("CAA.UnknownCritical", 1)
		return true, false
	}

	if len(caaSet.Unknown) > 0 {
		va.stats.Inc("CAA.WithUnknownNoncritical", 1)
	}

	if len(caaSet.Issue) == 0 && !wildcard {
		// Although CAA records exist, none of them pertain to issuance in this case.
		// (e.g. there is only an issuewild directive, but we are checking for a
		// non-wildcard identifier, or there is only an iodef or non-critical unknown
		// directive.)
		va.stats.Inc("CAA.NoneRelevant", 1)
		return true, true
	}

	// Per RFC 6844 Section 5.3 "issueWild properties MUST be ignored when
	// processing a request for a domain that is not a wildcard domain". Skip
	// checking `caaSet.Issuewild` if `wildcard` is false.
	if wildcard && len(caaSet.Issuewild) > 0 {
		// We are processing CAA for a wildcard authorization identifier and there
		// was at least one Issuewild CAA record in the set. This means we must
		// check that our CAA identity is present in the issueWild set.
		//
		for _, caaIssuewild := range caaSet.Issuewild {
			if extractIssuerDomain(caaIssuewild) == va.issuerDomain {
				va.stats.Inc("CAA.IssuewildAuthorized", 1)
				return true, true
			}
			// Since our identity is *not* present we must without checking the
			// `caaSet.Issue` identities because per RFC 6844 Section 5.3 if the domain
			// is a wildcard domain and there is at least one issuewild property then
			// "all issue properties MUST be ignored"
			return true, false
		}
	}

	// There are CAA records pertaining to issuance in our case. Note that this
	// includes the case of the unsatisfiable CAA record value ";", used to
	// prevent issuance by any CA under any circumstance.
	//
	// Our CAA identity must be found in the chosen checkSet. We perform this
	// check even if `wildcard` is true because we have already ruled out the
	// presence of `caaSet.Issuewild` records. RFC 6844 is not clear on whether an
	// Issue record may prevent issuance of a wildcard domain if there are no
	// Issuewild records so we take the most conservative stance and say they can.
	for _, caa := range caaSet.Issue {
		if extractIssuerDomain(caa) == va.issuerDomain {
			va.stats.Inc("CAA.Authorized", 1)
			return true, true
		}
	}

	// The list of authorized issuers is non-empty, but we are not in it. Fail.
	va.stats.Inc("CAA.Unauthorized", 1)
	return true, false
}

// Given a CAA record, assume that the Value is in the issue/issuewild format,
// that is, a domain name with zero or more additional key-value parameters.
// Returns the domain name, which may be "" (unsatisfiable).
func extractIssuerDomain(caa *dns.CAA) string {
	v := caa.Value
	v = strings.Trim(v, " \t") // Value can start and end with whitespace.
	idx := strings.IndexByte(v, ';')
	if idx < 0 {
		return v // no parameters; domain only
	}

	// Currently, ignore parameters. Unfortunately, the RFC makes no statement on
	// whether any parameters are critical. Treat unknown parameters as
	// non-critical.
	return strings.Trim(v[0:idx], " \t")
}
