package va

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"sync"

	"github.com/letsencrypt/boulder/core"
	corepb "github.com/letsencrypt/boulder/core/proto"
	berrors "github.com/letsencrypt/boulder/errors"
	"github.com/letsencrypt/boulder/identifier"
	"github.com/letsencrypt/boulder/probs"
	vapb "github.com/letsencrypt/boulder/va/proto"
	"github.com/miekg/dns"
)

type caaParams struct {
	accountURIID     int64
	validationMethod core.AcmeChallenge
}

func (va *ValidationAuthorityImpl) IsCAAValid(ctx context.Context, req *vapb.IsCAAValidRequest) (*vapb.IsCAAValidResponse, error) {
	if req.Domain == "" || req.ValidationMethod == "" || req.AccountURIID == 0 {
		return nil, berrors.InternalServerError("incomplete IsCAAValid request")
	}

	validationMethod := core.AcmeChallenge(req.ValidationMethod)
	if !validationMethod.IsValid() {
		return nil, berrors.InternalServerError("unrecognized validation method %q", req.ValidationMethod)
	}

	acmeID := identifier.ACMEIdentifier{
		Type:  identifier.DNS,
		Value: req.Domain,
	}
	params := &caaParams{
		accountURIID:     req.AccountURIID,
		validationMethod: validationMethod,
	}
	if prob := va.checkCAA(ctx, acmeID, params); prob != nil {
		detail := fmt.Sprintf("While processing CAA for %s: %s", req.Domain, prob.Detail)
		return &vapb.IsCAAValidResponse{
			Problem: &corepb.ProblemDetails{
				ProblemType: string(prob.Type),
				Detail:      replaceInvalidUTF8([]byte(detail)),
			},
		}, nil
	}
	return &vapb.IsCAAValidResponse{}, nil
}

// checkCAA performs a CAA lookup & validation for the provided identifier. If
// the CAA lookup & validation fail a problem is returned.
func (va *ValidationAuthorityImpl) checkCAA(
	ctx context.Context,
	identifier identifier.ACMEIdentifier,
	params *caaParams) *probs.ProblemDetails {
	if params == nil || params.validationMethod == "" || params.accountURIID == 0 {
		return probs.ServerInternal("expected validationMethod or accountURIID not provided to checkCAA")
	}

	foundAt, valid, response, err := va.checkCAARecords(ctx, identifier, params)
	if err != nil {
		return probs.DNS(err.Error())
	}

	va.log.AuditInfof("Checked CAA records for %s, [Present: %t, Account ID: %d, Challenge: %s, Valid for issuance: %t, Found at: %q] Response=%q",
		identifier.Value, foundAt != "", params.accountURIID, params.validationMethod, valid, foundAt, response)
	if !valid {
		return probs.CAA(fmt.Sprintf("CAA record for %s prevents issuance", foundAt))
	}
	return nil
}

// caaResult represents the result of querying CAA for a single name. It breaks
// the CAA resource records down by category, keeping only the issue and
// issuewild records. It also records whether any unrecognized RRs were marked
// critical, and stores the raw response text for logging and debugging.
type caaResult struct {
	name            string
	present         bool
	issue           []*dns.CAA
	issuewild       []*dns.CAA
	criticalUnknown bool
	dig             string
	err             error
}

// filterCAA processes a set of CAA resource records and picks out the only bits
// we care about. It returns two slices of CAA records, representing the issue
// records and the issuewild records respectively, and a boolean indicating
// whether any unrecognized records had the critical bit set.
func filterCAA(rrs []*dns.CAA) ([]*dns.CAA, []*dns.CAA, bool) {
	var issue, issuewild []*dns.CAA
	var criticalUnknown bool

	for _, caaRecord := range rrs {
		switch strings.ToLower(caaRecord.Tag) {
		case "issue":
			issue = append(issue, caaRecord)
		case "issuewild":
			issuewild = append(issuewild, caaRecord)
		case "iodef":
			// We support the iodef property tag insofar as we recognize it, but we
			// never choose to send notifications to the specified addresses. So we
			// do not store the contents of the property tag, but also avoid setting
			// the criticalUnknown bit if there are critical iodef tags.
			continue
		default:
			// The critical flag is the bit with significance 128. However, many CAA
			// record users have misinterpreted the RFC and concluded that the bit
			// with significance 1 is the critical bit. This is sufficiently
			// widespread that that bit must reasonably be considered an alias for
			// the critical bit. The remaining bits are 0/ignore as proscribed by the
			// RFC.
			if (caaRecord.Flag & (128 | 1)) != 0 {
				criticalUnknown = true
			}
		}
	}

	return issue, issuewild, criticalUnknown
}

// parallelCAALookup makes parallel requests for the target name and all parent
// names. It returns a slice of CAA results, with the results from querying the
// FQDN in the zeroth index, and the results from querying the TLD in the last
// index.
func (va *ValidationAuthorityImpl) parallelCAALookup(ctx context.Context, name string) []caaResult {
	labels := strings.Split(name, ".")
	results := make([]caaResult, len(labels))
	var wg sync.WaitGroup

	for i := 0; i < len(labels); i++ {
		// Start the concurrent DNS lookup.
		wg.Add(1)
		go func(name string, r *caaResult) {
			r.name = name
			var records []*dns.CAA
			records, r.dig, r.err = va.dnsClient.LookupCAA(ctx, name)
			if len(records) > 0 {
				r.present = true
			}
			r.issue, r.issuewild, r.criticalUnknown = filterCAA(records)
			wg.Done()
		}(strings.Join(labels[i:], "."), &results[i])
	}

	wg.Wait()
	return results
}

// selectCAA picks the relevant CAA resource record set to be used, i.e. the set
// for the "closest parent" of the FQDN in question, including the domain
// itself. If we encountered an error for a lookup before we found a successful,
// non-empty response, assume there could have been real records hidden by it,
// and return that error.
func selectCAA(rrs []caaResult) (*caaResult, error) {
	for _, res := range rrs {
		if res.err != nil {
			return nil, res.err
		}
		if res.present {
			return &res, nil
		}
	}
	return nil, nil
}

// getCAA returns the CAA Relevant Resource Set[1] for the given FQDN, i.e. the
// first CAA RRSet found by traversing upwards from the FQDN by removing the
// leftmost label. It returns nil if no RRSet is found on any parent of the
// given FQDN. The returned result also contains the raw CAA response, and an
// error if one is encountered while querying or parsing the records.
//
// [1]: https://datatracker.ietf.org/doc/html/rfc8659#name-relevant-resource-record-se
func (va *ValidationAuthorityImpl) getCAA(ctx context.Context, hostname string) (*caaResult, error) {
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
	return selectCAA(results)
}

// checkCAARecords fetches the CAA records for the given identifier and then
// validates them. If the identifier argument's value has a wildcard prefix then
// the prefix is stripped and validation will be performed against the base
// domain, honouring any issueWild CAA records encountered as appropriate.
// checkCAARecords returns four values: the first is a string indicating at
// which name (i.e. FQDN or parent thereof) CAA records were found, if any. The
// second is a bool indicating whether issuance for the identifier is valid. The
// unmodified *dns.CAA records that were processed/filtered are returned as the
// third argument. Any  errors encountered are returned as the fourth return
// value (or nil).
func (va *ValidationAuthorityImpl) checkCAARecords(
	ctx context.Context,
	identifier identifier.ACMEIdentifier,
	params *caaParams) (string, bool, string, error) {
	hostname := strings.ToLower(identifier.Value)
	// If this is a wildcard name, remove the prefix
	var wildcard bool
	if strings.HasPrefix(hostname, `*.`) {
		hostname = strings.TrimPrefix(identifier.Value, `*.`)
		wildcard = true
	}
	caaSet, err := va.getCAA(ctx, hostname)
	if err != nil {
		return "", false, "", err
	}
	raw := ""
	if caaSet != nil {
		raw = caaSet.dig
	}
	valid, foundAt := va.validateCAA(caaSet, wildcard, params)
	return foundAt, valid, raw, nil
}

// validateCAA checks a provided *caaResult. When the wildcard argument is true
// this means the issueWild records must be validated as well. This function
// returns a boolean indicating whether issuance is allowed by this set of CAA
// records, and a string indicating the name at which the CAA records allowing
// issuance were found (if any -- since finding no records at all allows
// issuance).
func (va *ValidationAuthorityImpl) validateCAA(caaSet *caaResult, wildcard bool, params *caaParams) (bool, string) {
	if caaSet == nil {
		// No CAA records found, can issue
		va.metrics.caaCounter.WithLabelValues("no records").Inc()
		return true, ""
	}

	if caaSet.criticalUnknown {
		// Contains unknown critical directives
		va.metrics.caaCounter.WithLabelValues("record with unknown critical directive").Inc()
		return false, caaSet.name
	}

	if len(caaSet.issue) == 0 && !wildcard {
		// Although CAA records exist, none of them pertain to issuance in this case.
		// (e.g. there is only an issuewild directive, but we are checking for a
		// non-wildcard identifier, or there is only an iodef or non-critical unknown
		// directive.)
		va.metrics.caaCounter.WithLabelValues("no relevant records").Inc()
		return true, caaSet.name
	}

	// Per RFC 8659 Section 5.3:
	//   - "Each issuewild Property MUST be ignored when processing a request for
	//     an FQDN that is not a Wildcard Domain Name."; and
	//   - "If at least one issuewild Property is specified in the Relevant RRset
	//     for a Wildcard Domain Name, each issue Property MUST be ignored when
	//     processing a request for that Wildcard Domain Name."
	// So we default to checking the `caaSet.Issue` records and only check
	// `caaSet.Issuewild` when `wildcard` is true and there are 1 or more
	// `Issuewild` records.
	records := caaSet.issue
	if wildcard && len(caaSet.issuewild) > 0 {
		records = caaSet.issuewild
	}

	// There are CAA records pertaining to issuance in our case. Note that this
	// includes the case of the unsatisfiable CAA record value ";", used to
	// prevent issuance by any CA under any circumstance.
	//
	// Our CAA identity must be found in the chosen checkSet.
	for _, caa := range records {
		parsedDomain, parsedParams, err := parseCAARecord(caa)
		if err != nil {
			continue
		}

		if !caaDomainMatches(parsedDomain, va.issuerDomain) {
			continue
		}

		if !caaAccountURIMatches(parsedParams, va.accountURIPrefixes, params.accountURIID) {
			continue
		}

		if !caaValidationMethodMatches(parsedParams, params.validationMethod) {
			continue
		}

		va.metrics.caaCounter.WithLabelValues("authorized").Inc()
		return true, caaSet.name
	}

	// The list of authorized issuers is non-empty, but we are not in it. Fail.
	va.metrics.caaCounter.WithLabelValues("unauthorized").Inc()
	return false, caaSet.name
}

// parseCAARecord extracts the domain and parameters (if any) from a
// issue/issuewild CAA record. This follows RFC 8659 Section 4.2 and Section 4.3
// (https://www.rfc-editor.org/rfc/rfc8659.html#section-4). It returns the
// domain name (which may be the empty string if the record forbids issuance)
// and a tag-value map of CAA parameters, or a descriptive error if the record
// is malformed.
func parseCAARecord(caa *dns.CAA) (string, map[string]string, error) {
	isWSP := func(r rune) bool {
		return r == '\t' || r == ' '
	}

	// Semi-colons (ASCII 0x3B) are prohibited from being specified in the
	// parameter tag or value, hence we can simply split on semi-colons.
	parts := strings.Split(caa.Value, ";")
	domain := strings.TrimFunc(parts[0], isWSP)
	paramList := parts[1:]
	parameters := make(map[string]string)

	// Handle the case where a semi-colon is specified following the domain
	// but no parameters are given.
	if len(paramList) == 1 && strings.TrimFunc(paramList[0], isWSP) == "" {
		return domain, parameters, nil
	}

	for _, parameter := range paramList {
		// A parameter tag cannot include equal signs (ASCII 0x3D),
		// however they are permitted in the value itself.
		tv := strings.SplitN(parameter, "=", 2)
		if len(tv) != 2 {
			return "", nil, fmt.Errorf("parameter not formatted as tag=value: %q", parameter)
		}

		tag := strings.TrimFunc(tv[0], isWSP)
		//lint:ignore S1029,SA6003 we iterate over runes because the RFC specifies ascii codepoints.
		for _, r := range []rune(tag) {
			// ASCII alpha/digits.
			// tag = (ALPHA / DIGIT) *( *("-") (ALPHA / DIGIT))
			if r < 0x30 || (r > 0x39 && r < 0x41) || (r > 0x5a && r < 0x61) || r > 0x7a {
				return "", nil, fmt.Errorf("tag contains disallowed character: %q", tag)
			}
		}

		value := strings.TrimFunc(tv[1], isWSP)
		//lint:ignore S1029,SA6003 we iterate over runes because the RFC specifies ascii codepoints.
		for _, r := range []rune(value) {
			// ASCII without whitespace/semi-colons.
			// value = *(%x21-3A / %x3C-7E)
			if r < 0x21 || (r > 0x3a && r < 0x3c) || r > 0x7e {
				return "", nil, fmt.Errorf("value contains disallowed character: %q", value)
			}
		}

		parameters[tag] = value
	}

	return domain, parameters, nil
}

// caaDomainMatches checks that the issuer domain name listed in the parsed
// CAA record matches the domain name we expect.
func caaDomainMatches(caaDomain string, issuerDomain string) bool {
	return caaDomain == issuerDomain
}

// caaAccountURIMatches checks that the accounturi CAA parameter, if present,
// matches one of the specific account URIs we expect. We support multiple
// account URI prefixes to handle accounts which were registered under ACMEv1.
// See RFC 8657 Section 3: https://www.rfc-editor.org/rfc/rfc8657.html#section-3
func caaAccountURIMatches(caaParams map[string]string, accountURIPrefixes []string, accountID int64) bool {
	accountURI, ok := caaParams["accounturi"]
	if !ok {
		return true
	}

	// If the accounturi is not formatted according to RFC 3986, reject it.
	_, err := url.Parse(accountURI)
	if err != nil {
		return false
	}

	for _, prefix := range accountURIPrefixes {
		if accountURI == fmt.Sprintf("%s%d", prefix, accountID) {
			return true
		}
	}
	return false
}

var validationMethodRegexp = regexp.MustCompile(`^[[:alnum:]-]+$`)

// caaValidationMethodMatches checks that the validationmethods CAA parameter,
// if present, contains the exact name of the ACME validation method used to
// validate this domain.
// See RFC 8657 Section 4: https://www.rfc-editor.org/rfc/rfc8657.html#section-4
func caaValidationMethodMatches(caaParams map[string]string, method core.AcmeChallenge) bool {
	commaSeparatedMethods, ok := caaParams["validationmethods"]
	if !ok {
		return true
	}

	for _, m := range strings.Split(commaSeparatedMethods, ",") {
		// If any listed method does not match the ABNF 1*(ALPHA / DIGIT / "-"),
		// immediately reject the whole record.
		if !validationMethodRegexp.MatchString(m) {
			return false
		}

		caaMethod := core.AcmeChallenge(m)
		if !caaMethod.IsValid() {
			continue
		}

		if caaMethod == method {
			return true
		}
	}
	return false
}
