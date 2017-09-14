package va

import (
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
	})

	if prob != nil {
		typ := string(prob.Type)
		return &vapb.IsCAAValidResponse{
			Problem: &corepb.ProblemDetails{
				ProblemType: &typ,
				Detail:      &prob.Detail,
			},
		}, nil
	}
	return &vapb.IsCAAValidResponse{}, nil
}

func (va *ValidationAuthorityImpl) checkCAA(ctx context.Context, identifier core.AcmeIdentifier) *probs.ProblemDetails {
	present, valid, err := va.checkCAARecords(ctx, identifier)
	if err != nil {
		return probs.ConnectionFailure(err.Error())
	}
	va.log.AuditInfo(fmt.Sprintf(
		"Checked CAA records for %s, [Present: %t, Valid for issuance: %t]",
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

// parentsDomains returns a list of all parent domains, in order from longest to
// shortest.
func parentDomains(fqdn string) []string {
	var result []string
	labels := strings.Split(strings.TrimRight(fqdn, "."), ".")
	for i := 1; i < len(labels); i++ {
		result = append(result, strings.Join(labels[i:], "."))
	}
	return result
}

// Implement pre-erratum 5065 style tree-climbing CAA. Note: a strict
// interpretation of pre-5065 indicates a linear lookup path - if there is any
// CNAME at all, that precludes further tree-climbing on the original FQDN. This
// is clearly wrong. We implement a hybrid approach that is strictly more
// conservative: We always do full tree-climbing on the original FQDN (by virtue
// of parallelCAALookup. When the LegacyCAA flag is enabled, we also
// do linear tree climbing on single-level aliases.
func (va *ValidationAuthorityImpl) treeClimbingLookupCAA(ctx context.Context, fqdn string) ([]*dns.CAA, error) {
	// We will do an (arbitrary) maximum of 15 tree-climbing queries to avoid CNAME/CAA
	// hybrid loops
	maxAttempts := 15
	return va.treeClimbingLookupCAAWithCount(ctx, fqdn, &maxAttempts)
}

func (va *ValidationAuthorityImpl) treeClimbingLookupCAAWithCount(ctx context.Context, fqdn string, attemptsRemaining *int) ([]*dns.CAA, error) {
	if *attemptsRemaining < 1 {
		return nil, fmt.Errorf("too many CNAMEs when looking up CAA")
	}
	*attemptsRemaining--
	caas, cnames, err := va.dnsClient.LookupCAA(ctx, fqdn)
	if err != nil {
		return nil, err
	} else if len(caas) > 0 {
		return caas, nil
	} else if len(cnames) > 0 {
		// CNAMEs are returned in order from the original fqdn to the ultimate
		// target. However, CAA wants us to check them in order from the ultimate
		// target back to the original FQDN.
		for i := len(cnames) - 1; i >= 0; i-- {
			// Start the tree climbing directly with the parent domains of each
			// target, because the target itself has already been queried by Unbound
			// as part of the original LookupCAA, and any CNAMEs are already in this
			// list.
			newTargets := parentDomains(cnames[i].Target)
			for _, newTarget := range newTargets {
				caas, err := va.treeClimbingLookupCAAWithCount(ctx, newTarget, attemptsRemaining)
				if len(caas) != 0 || err != nil {
					return caas, err
				}
			}
		}
	}
	return nil, nil
}

type lookuperFunc func(context.Context, string) ([]*dns.CAA, error)

func (va *ValidationAuthorityImpl) parallelCAALookup(ctx context.Context, name string, lookuper lookuperFunc) []caaResult {
	labels := strings.Split(name, ".")
	results := make([]caaResult, len(labels))
	var wg sync.WaitGroup

	for i := 0; i < len(labels); i++ {
		// Start the concurrent DNS lookup.
		wg.Add(1)
		go func(name string, r *caaResult) {
			r.records, r.err = lookuper(ctx, name)
			wg.Done()
		}(strings.Join(labels[i:], "."), &results[i])
	}

	wg.Wait()
	return results
}

func (va *ValidationAuthorityImpl) getCAASet(ctx context.Context, hostname string) (*CAASet, error) {
	hostname = strings.TrimRight(hostname, ".")

	lookuper := func(ctx context.Context, fqdn string) ([]*dns.CAA, error) {
		caas, _, err := va.dnsClient.LookupCAA(ctx, fqdn)
		return caas, err
	}
	if features.Enabled(features.LegacyCAA) {
		lookuper = va.treeClimbingLookupCAA
	}

	// See RFC 6844 "Certification Authority Processing" for pseudocode.
	// Essentially: check CAA records for the FDQN to be issued, and all
	// parent domains.
	//
	// The lookups are performed in parallel in order to avoid timing out
	// the RPC call.
	//
	// We depend on our resolver to snap CNAME and DNAME records.
	results := va.parallelCAALookup(ctx, hostname, lookuper)
	return parseResults(results)
}

func (va *ValidationAuthorityImpl) checkCAARecords(ctx context.Context, identifier core.AcmeIdentifier) (present, valid bool, err error) {
	hostname := strings.ToLower(identifier.Value)
	caaSet, err := va.getCAASet(ctx, hostname)
	if err != nil {
		return false, false, err
	}
	present, valid = va.validateCAASet(caaSet)
	return present, valid, nil
}

func (va *ValidationAuthorityImpl) validateCAASet(caaSet *CAASet) (present, valid bool) {
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

	if len(caaSet.Issue) == 0 {
		// Although CAA records exist, none of them pertain to issuance in this case.
		// (e.g. there is only an issuewild directive, but we are checking for a
		// non-wildcard identifier, or there is only an iodef or non-critical unknown
		// directive.)
		va.stats.Inc("CAA.NoneRelevant", 1)
		return true, true
	}

	// There are CAA records pertaining to issuance in our case. Note that this
	// includes the case of the unsatisfiable CAA record value ";", used to
	// prevent issuance by any CA under any circumstance.
	//
	// Our CAA identity must be found in the chosen checkSet.
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
