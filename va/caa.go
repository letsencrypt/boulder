package va

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/letsencrypt/boulder/core"
	corepb "github.com/letsencrypt/boulder/core/proto"
	"github.com/letsencrypt/boulder/features"
	"github.com/letsencrypt/boulder/probs"
	vapb "github.com/letsencrypt/boulder/va/proto"
	"github.com/miekg/dns"
	"golang.org/x/net/context"
)

func (va *ValidationAuthorityImpl) IsCAAValid(
	ctx context.Context,
	req *vapb.IsCAAValidRequest,
) (*vapb.IsCAAValidResponse, error) {
	prob := va.checkCAA(ctx, core.AcmeIdentifier{
		Type:  core.IdentifierDNS,
		Value: *req.Domain,
	}, req.ValidationMethod)

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
// the CAA lookup & validation fail a problem is returned.
func (va *ValidationAuthorityImpl) checkCAA(
	ctx context.Context,
	identifier core.AcmeIdentifier,
	challengeType *string) *probs.ProblemDetails {
	present, valid, records, err := va.checkCAARecords(ctx, identifier)
	if err != nil {
		return probs.DNS("%v", err)
	}

	recordsStr, err := json.Marshal(&records)
	if err != nil {
		return probs.CAA("CAA records for %s were malformed", identifier.Value)
	}

	va.log.AuditInfof("Checked CAA records for %s, [Present: %t, Valid for issuance: %t] Records=%s",
		identifier.Value, present, valid, recordsStr)
	if !valid {
		return probs.CAA("CAA record for %s prevents issuance", identifier.Value)
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
		switch strings.ToLower(caaRecord.Tag) {
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

func parseResults(results []caaResult) (*CAASet, []*dns.CAA, error) {
	// Return first result
	for _, res := range results {
		if res.err != nil {
			return nil, nil, res.err
		}
		if len(res.records) > 0 {
			return newCAASet(res.records), res.records, nil
		}
	}
	return nil, nil, nil
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

func (va *ValidationAuthorityImpl) getCAASet(ctx context.Context, hostname string) (*CAASet, []*dns.CAA, error) {
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
// validates them. If the identifier argument's value has a wildcard prefix then
// the prefix is stripped and validation will be performed against the base
// domain, honouring any issueWild CAA records encountered as apppropriate.
// checkCAARecords returns four values: the first is a bool indicating whether
// CAA records were present after filtering for known/supported CAA tags. The
// second is a bool indicating whether issuance for the identifier is valid. The
// unmodified *dns.CAA records that were processed/filtered are returned as the
// third argument. Any  errors encountered are returned as the fourth return
// value (or nil).
func (va *ValidationAuthorityImpl) checkCAARecords(
	ctx context.Context,
	identifier core.AcmeIdentifier,
	challengeType *string) (bool, bool, []*dns.CAA, error) {
	hostname := strings.ToLower(identifier.Value)
	// If this is a wildcard name, remove the prefix
	var wildcard bool
	if strings.HasPrefix(hostname, `*.`) {
		hostname = strings.TrimPrefix(identifier.Value, `*.`)
		wildcard = true
	}
	caaSet, records, err := va.getCAASet(ctx, hostname)
	if err != nil {
		return false, false, nil, err
	}
	present, valid = va.validateCAASet(caaSet, wildcard, challengeType)
	return present, valid, records, nil
}

func containsMethod(commaSeparatedMethods, method string) bool {
	for _, m := range strings.Split(commaSeparatedMethods, ",") {
		if method == m {
			return true
		}
	}
	return false
}

// validateCAASet checks a provided *CAASet. When the wildcard argument is true
// this means the CAASet's issueWild records must be validated as well. This
// function returns two booleans: the first indicates whether the CAASet was
// empty, the second indicates whether the CAASet is valid for issuance to
// proceed.
func (va *ValidationAuthorityImpl) validateCAASet(caaSet *CAASet, wildcard bool, challengeType *string) (present, valid bool) {
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
	// processing a request for a domain that is not a wildcard domain" so we
	// default to checking the `caaSet.Issue` records and only check
	// `caaSet.Issuewild` when `wildcard` is true and there is >0 `Issuewild`
	// records.
	records := caaSet.Issue
	if wildcard && len(caaSet.Issuewild) > 0 {
		records = caaSet.Issuewild
	}

	// There are CAA records pertaining to issuance in our case. Note that this
	// includes the case of the unsatisfiable CAA record value ";", used to
	// prevent issuance by any CA under any circumstance.
	//
	// Our CAA identity must be found in the chosen checkSet.
	for _, caa := range records {
		caaIssuerDomain, caaParameters := extractIssuerDomainAndParameters(caa)
		if caaIssuerDomain != va.issuerDomain {
			continue
		}

		if features.Enabled(features.CAAValidationMethods) {
			// Check the validation-methods CAA parameter as defined
			// in section 4 of the draft CAA ACME RFC:
			// https://tools.ietf.org/html/draft-ietf-acme-caa-03
			caaMethods, ok := caaParameters["validation-methods"]
			if ok {
				if challengeType == nil {
					continue
				}
				if !containsMethod(caaMethods, *challengeType) {
					continue
				}
			}
		}

		va.stats.Inc("CAA.Authorized", 1)
		return true, true
	}

	// The list of authorized issuers is non-empty, but we are not in it. Fail.
	va.stats.Inc("CAA.Unauthorized", 1)
	return true, false
}

// Given a CAA record, assume that the Value is in the issue/issuewild format,
// that is, a domain name with zero or more additional key-value parameters.
// Returns the domain name, which may be "" (unsatisfiable), and a tag-value map of parameters.
func extractIssuerDomainAndParameters(caa *dns.CAA) (domain string, parameters map[string]string) {
	isIssueSpace := func(r rune) bool {
		return r == '\t' || r == ' '
	}

	v := strings.SplitN(caa.Value, ";", 2)
	domain = strings.TrimFunc(v[0], isIssueSpace)
	parameters = make(map[string]string)

	if len(v) == 2 {
		for _, s := range strings.FieldsFunc(v[1], isIssueSpace) {
			if kv := strings.SplitN(s, "=", 2); len(kv) == 2 {
				parameters[kv[0]] = kv[1]
			}
		}
	}

	return domain, parameters
}
