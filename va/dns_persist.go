package va

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/idna"
	"golang.org/x/text/unicode/norm"

	"github.com/letsencrypt/boulder/core"
	berrors "github.com/letsencrypt/boulder/errors"
	"github.com/letsencrypt/boulder/identifier"
)

type dnsPersistIssueValue struct {
	issuerDomain string
	accountURI   string
	policy       string
	persistUntil *time.Time
}

// NormalizeIssuerDomainName normalizes an RFC 8659 issuer-domain-name per
// draft-ietf-acme-dns-persist-00, Section 9.1.1: case-fold to lowercase, apply
// Unicode NFC normalization, convert to A-label (Punycode), remove any trailing
// dot, and ensure the result is no more than 253 octets in length. If
// normalization fails, an error is returned.
func NormalizeIssuerDomainName(name string) (string, error) {
	name = strings.ToLower(name)
	name = norm.NFC.String(name)
	name, err := idna.Lookup.ToASCII(name)
	if err != nil {
		return "", fmt.Errorf("converting issuer domain name %q to ASCII: %w", name, err)
	}
	name = strings.TrimSuffix(name, ".")
	if len(name) > 253 {
		return "", fmt.Errorf("issuer domain name %q exceeds 253 octets (%d)", name, len(name))
	}
	return name, nil
}

// trimWSP trims RFC 5234 WSP (SP / HTAB) characters, as referenced by RFC 8659,
// from both ends of the input string.
func trimWSP(input string) string {
	return strings.TrimFunc(input, func(r rune) bool {
		return r == ' ' || r == '\t'
	})
}

// splitIssueValue splits and returns an RFC 8659 issue-value into
// issuer-domain-name and raw parameter segments. If parsing fails, zero values
// are returned.
func splitIssueValue(raw string) (string, []string) {
	// Split into issuer-domain-name and parameters.
	parts := strings.Split(raw, ";")
	if len(parts) == 0 {
		return "", nil
	}
	// Parse issuer-domain-name.
	issuerDomainName := trimWSP(parts[0])
	if issuerDomainName == "" {
		return "", nil
	}
	return issuerDomainName, parts[1:]
}

// parseDNSPersistIssueValue parses the raw parameter segments of an RFC 8659
// issue-value from a dns-persist-01 TXT record. It returns an error if any
// recognized parameter is malformed or duplicated.
func parseDNSPersistIssueValue(issuerDomainName string, paramsRaw []string) (*dnsPersistIssueValue, error) {
	result := &dnsPersistIssueValue{issuerDomain: issuerDomainName}

	seenTags := make(map[string]bool)

	for _, param := range paramsRaw {
		// Clean optional WSP from the parameter.
		param = trimWSP(param)
		if param == "" {
			return nil, errors.New("empty parameter or trailing semicolon provided")
		}

		// Capture each tag=value pair.
		tagValue := strings.SplitN(param, "=", 2)
		if len(tagValue) != 2 {
			return nil, fmt.Errorf("malformed parameter %q should be tag=value pair", param)
		}
		tag := trimWSP(tagValue[0])
		value := trimWSP(tagValue[1])
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
			persistUntil := time.Unix(persistUntilVal, 0).UTC()
			result.persistUntil = &persistUntil
		}
	}
	return result, nil
}

func (va *ValidationAuthorityImpl) validateDNSPersist01(ctx context.Context, ident identifier.ACMEIdentifier, validAccountURI string, wildcardName bool) ([]core.ValidationRecord, error) {
	if ident.Type != identifier.TypeDNS {
		return nil, berrors.MalformedError("Identifier type for DNS-PERSIST-01 challenge was not DNS")
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

	allowedIssuer := va.issuerDomain
	if allowedIssuer == "" {
		// Belt and suspenders check: the VA should not have been configured to
		// perform DNS-PERSIST-01 validation if it does not have an issuer
		// domain name configured for comparison.
		return nil, berrors.InternalServerError("no issuer domain name configured for DNS-PERSIST-01 challenge validation")
	}

	var syntaxErrs []string
	var authorizationErrs []string
	for _, rr := range txts.Final {
		record := strings.Join(rr.Txt, "")
		receivedIssuer, paramsRaw := splitIssueValue(record)
		normalizedIssuer, err := NormalizeIssuerDomainName(receivedIssuer)
		if err != nil || normalizedIssuer != allowedIssuer {
			continue
		}

		params, err := parseDNSPersistIssueValue(receivedIssuer, paramsRaw)
		if err != nil {
			// We know if this record was intended for us but it is malformed,
			// we can continue checking other records but we should report the
			// syntax error if no other record authorizes the challenge.
			syntaxErrs = append(syntaxErrs, fmt.Sprintf(
				"Parsing DNS-PERSIST-01 challenge TXT record with issuer-domain-name %q: %s", receivedIssuer, err))
			continue
		}
		if params.accountURI == "" {
			syntaxErrs = append(syntaxErrs, fmt.Sprintf(
				"Parsing DNS-PERSIST-01 challenge TXT record with issuer-domain-name %q: missing mandatory accountURI parameter", receivedIssuer))
			continue
		}
		if params.accountURI != validAccountURI {
			authorizationErrs = append(authorizationErrs, fmt.Sprintf(
				"Parsing DNS-PERSIST-01 challenge TXT record with issuer-domain-name %q: accounturi mismatch: expected %q, got %q",
				receivedIssuer, validAccountURI, params.accountURI))
			continue
		}
		// Per draft-ietf-acme-dns-persist-00, the policy parameter's tag
		// and defined values MUST be treated as case-insensitive. If the
		// policy parameter's value is anything other than "wildcard", the
		// CA MUST proceed as if the policy parameter were not present.
		policyLower := strings.ToLower(params.policy)
		if wildcardName && policyLower != "wildcard" {
			authorizationErrs = append(authorizationErrs, fmt.Sprintf(
				"Parsing DNS-PERSIST-01 challenge TXT record with issuer-domain-name %q: policy mismatch: expected \"wildcard\", got %q",
				receivedIssuer, params.policy))
			continue
		}
		if params.persistUntil != nil && validatedAt.After(*params.persistUntil) {
			authorizationErrs = append(authorizationErrs, fmt.Sprintf(
				"Parsing DNS-PERSIST-01 challenge TXT record with issuer-domain-name %q, validation time %s is after persistUntil %s",
				receivedIssuer, validatedAt.Format(time.RFC3339), params.persistUntil.Format(time.RFC3339)))
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
