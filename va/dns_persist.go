package va

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/letsencrypt/boulder/core"
	berrors "github.com/letsencrypt/boulder/errors"
	"github.com/letsencrypt/boulder/identifier"
)

type dnsPersistIssueValue struct {
	issuerDomain string
	accountURI   string
	policy       string
	persistUntil time.Time
}

// isWSP checks if a rune is an RFC 5234 WSP (SP / HTAB) character, as
// referenced by RFC 8659.
func isWSP(r rune) bool {
	return r == '\t' || r == ' '
}

// parseDNSPersistIssueValue parses the raw parameter segments of an RFC 8659
// issue-value from a dns-persist-01 TXT record. It returns an error if any
// recognized parameter is malformed or duplicated.
func parseDNSPersistIssueValue(issuerDomainName string, paramsRaw []string) (*dnsPersistIssueValue, error) {
	result := &dnsPersistIssueValue{issuerDomain: issuerDomainName}

	seenTags := make(map[string]bool)

	for _, param := range paramsRaw {
		// Clean optional WSP from the parameter.
		param = strings.TrimFunc(param, isWSP)
		if param == "" {
			return nil, errors.New("empty parameter or trailing semicolon provided")
		}

		// Capture each tag=value pair.
		tagValue := strings.SplitN(param, "=", 2)
		if len(tagValue) != 2 {
			return nil, fmt.Errorf("malformed parameter %q should be tag=value pair", param)
		}
		tag := strings.TrimFunc(tagValue[0], isWSP)
		value := strings.TrimFunc(tagValue[1], isWSP)
		if tag == "" {
			return nil, fmt.Errorf("malformed parameter %q, empty tag", param)
		}

		// Per the RFC 8659, matching of tags is case insensitive; canonicalize
		// before checking whether the tag is recognized.
		canonicalTag := strings.ToLower(tag)

		switch canonicalTag {
		case "accounturi", "policy", "persistuntil":
			// Recognized tag — fall through to validation below.
		default:
			// Per draft-ietf-acme-dns-persist-00, "the server MUST ignore any
			// parameter within the issue-value that has an unrecognized tag."
			continue
		}
		if seenTags[canonicalTag] {
			return nil, fmt.Errorf("duplicate parameter %q", tag)
		}
		seenTags[canonicalTag] = true

		// Ensure values contain no whitespace, control, or non-ASCII
		// characters.
		for _, r := range value {
			if (r >= 0x21 && r <= 0x3A) || (r >= 0x3C && r <= 0x7E) {
				continue
			}
			return nil, fmt.Errorf("malformed value %q for tag %q", value, tag)
		}

		switch canonicalTag {
		case "accounturi":
			if value == "" {
				return nil, fmt.Errorf("empty value provided for mandatory accounturi")
			}
			result.accountURI = value

		case "policy":
			result.policy = value

		case "persistuntil":
			persistUntilVal, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("malformed persistUntil timestamp %q", value)
			}
			result.persistUntil = time.Unix(persistUntilVal, 0).UTC()
		}
	}
	return result, nil
}

// parseDNSPersistRecord parses a raw TXT record string into a
// dnsPersistIssueValue. It returns ("", nil, nil) if the record's
// issuer-domain-name is empty or does not match allowedIssuer.
func parseDNSPersistRecord(record string, allowedIssuer string) (string, *dnsPersistIssueValue, error) {
	// Split into issuer-domain-name and parameters per RFC 8659.
	parts := strings.Split(record, ";")
	receivedIssuer := strings.TrimFunc(parts[0], isWSP)
	if receivedIssuer == "" {
		return "", nil, nil
	}

	normalizedIssuer, err := core.NormalizeIssuerDomainName(receivedIssuer)
	if err != nil || normalizedIssuer != allowedIssuer {
		return "", nil, nil
	}

	params, err := parseDNSPersistIssueValue(receivedIssuer, parts[1:])
	if err != nil {
		return receivedIssuer, nil, err
	}
	return receivedIssuer, params, nil
}

// checkDNSPersistRecord checks whether a parsed dns-persist-01 record
// authorizes issuance for the given account URI and wildcard status at the
// given time. It returns nil if the record authorizes issuance, a
// berrors.Malformed error for syntax problems, or a berrors.Unauthorized error
// for authorization failures.
func checkDNSPersistRecord(params *dnsPersistIssueValue, validAccountURI string, wildcardName bool, validatedAt time.Time) error {
	if params.accountURI == "" {
		return berrors.MalformedError("missing mandatory accountURI parameter")
	}
	if params.accountURI != validAccountURI {
		return berrors.UnauthorizedError("accounturi mismatch: expected %q, got %q", validAccountURI, params.accountURI)
	}
	// Per draft-ietf-acme-dns-persist-00, the policy parameter's tag and
	// defined values MUST be treated as case-insensitive. If the policy
	// parameter's value is anything other than "wildcard", the CA MUST proceed
	// as if the policy parameter were not present.
	if wildcardName && strings.ToLower(params.policy) != "wildcard" {
		return berrors.UnauthorizedError("policy mismatch: expected \"wildcard\", got %q", params.policy)
	}
	if !params.persistUntil.IsZero() && validatedAt.After(params.persistUntil) {
		return berrors.UnauthorizedError("validation time %s is after persistUntil %s",
			validatedAt.Format(time.RFC3339), params.persistUntil.Format(time.RFC3339))
	}
	return nil
}

func (va *ValidationAuthorityImpl) validateDNSPersist01(ctx context.Context, ident identifier.ACMEIdentifier, validAccountURI string, wildcardName bool) ([]core.ValidationRecord, error) {
	if ident.Type != identifier.TypeDNS {
		return nil, berrors.MalformedError("Identifier type for DNS-PERSIST-01 challenge was not DNS")
	}

	if va.issuerDomain == "" {
		// Belt and suspenders check: the VA should not have been configured to
		// perform DNS-PERSIST-01 validation if it does not have an issuer
		// domain name configured for comparison.
		return nil, berrors.InternalServerError("no issuer domain name configured for DNS-PERSIST-01 challenge validation")
	}

	challengeSubdomain := fmt.Sprintf("%s.%s", core.DNSPersistPrefix, ident.Value)
	txts, resolver, err := va.dnsClient.LookupTXT(ctx, challengeSubdomain)
	if err != nil {
		return nil, berrors.DNSError("Retrieving TXT records for DNS-PERSIST-01 challenge: %s", err)
	}
	if len(txts.Final) == 0 {
		return nil, berrors.UnauthorizedError("No TXT record found for DNS-PERSIST-01 challenge")
	}
	validatedAt := va.clk.Now().UTC()

	var syntaxErrs []string
	var authorizationErrs []string
	for _, rr := range txts.Final {
		record := strings.Join(rr.Txt, "")

		receivedIssuer, params, err := parseDNSPersistRecord(record, va.issuerDomain)
		if err != nil {
			syntaxErrs = append(syntaxErrs, fmt.Sprintf(
				"Parsing DNS-PERSIST-01 challenge TXT record with issuer-domain-name %q: %s", receivedIssuer, err))
			continue
		}
		if params == nil {
			// Record didn't match our issuer domain, skip.
			continue
		}

		err = checkDNSPersistRecord(params, validAccountURI, wildcardName, validatedAt)
		if err != nil {
			msg := fmt.Sprintf(
				"Parsing DNS-PERSIST-01 challenge TXT record with issuer-domain-name %q: %s", receivedIssuer, err)
			if errors.Is(err, berrors.Malformed) {
				syntaxErrs = append(syntaxErrs, msg)
			} else {
				authorizationErrs = append(authorizationErrs, msg)
			}
			continue
		}

		return []core.ValidationRecord{{
			Hostname:      ident.Value,
			ResolverAddrs: []string{resolver},
		}}, nil
	}

	if len(syntaxErrs) > 0 {
		return nil, berrors.MalformedError("%s", strings.Join(syntaxErrs, "; "))
	}
	if len(authorizationErrs) > 0 {
		return nil, berrors.UnauthorizedError("%s", strings.Join(authorizationErrs, "; "))
	}
	return nil, berrors.UnauthorizedError("No valid TXT record found for DNS-PERSIST-01 challenge")
}
