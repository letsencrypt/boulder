package va

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/letsencrypt/boulder/core"
	berrors "github.com/letsencrypt/boulder/errors"
	"github.com/letsencrypt/boulder/identifier"
)

type dnsPersistIssueValueParams struct {
	accountURI   string
	policy       string
	persistUntil time.Time
}

// isWSP checks if a rune is an RFC 5234 WSP (SP / HTAB) character, as
// referenced by RFC 8659.
func isWSP(r rune) bool {
	return r == '\t' || r == ' '
}

// parseDNSPersistRecord parses a raw TXT record string per RFC 8659 issue-value
// syntax. It returns the issuer-domain-name and parsed parameters on success,
// or an error if the record is malformed.
func parseDNSPersistRecord(record string) (string, *dnsPersistIssueValueParams, error) {
	parts := strings.Split(record, ";")
	issuer := strings.TrimFunc(parts[0], isWSP)
	if issuer == "" {
		return "", nil, errors.New("empty issuer-domain-name")
	}

	params := &dnsPersistIssueValueParams{}

	seenTags := make(map[string]bool)
	seenTag := func(tag string) bool {
		if seenTags[tag] {
			return true
		}
		seenTags[tag] = true
		return false
	}

	for _, param := range parts[1:] {
		// Clean optional WSP from the parameter.
		param = strings.TrimFunc(param, isWSP)
		if param == "" {
			return issuer, nil, errors.New("empty parameter or trailing semicolon provided")
		}

		// Capture each tag=value pair.
		tagValue := strings.SplitN(param, "=", 2)
		if len(tagValue) != 2 {
			return issuer, nil, fmt.Errorf("malformed parameter %q should be tag=value pair", param)
		}
		tag := strings.TrimFunc(tagValue[0], isWSP)
		value := strings.TrimFunc(tagValue[1], isWSP)
		if tag == "" {
			return issuer, nil, fmt.Errorf("malformed parameter %q, empty tag", param)
		}

		// Ensure values contain no whitespace, control, or non-ASCII
		// characters.
		for _, r := range value {
			if (r >= 0x21 && r <= 0x3A) || (r >= 0x3C && r <= 0x7E) {
				continue
			}
			return issuer, nil, fmt.Errorf("malformed value %q for tag %q", value, tag)
		}

		// Per the RFC 8659, matching of tags is case insensitive; canonicalize
		// before checking whether the tag is recognized.
		canonicalTag := strings.ToLower(tag)

		switch canonicalTag {
		case "accounturi":
			if seenTag(canonicalTag) {
				return issuer, nil, fmt.Errorf("duplicate parameter %q", tag)
			}
			if value == "" {
				return issuer, nil, fmt.Errorf("empty value provided for mandatory accounturi")
			}
			params.accountURI = value

		case "policy":
			if seenTag(canonicalTag) {
				return issuer, nil, fmt.Errorf("duplicate parameter %q", tag)
			}
			params.policy = value

		case "persistuntil":
			if seenTag(canonicalTag) {
				return issuer, nil, fmt.Errorf("duplicate parameter %q", tag)
			}
			// strconv.ParseInt accepts a leading sign, but
			// draft-ietf-acme-dns-persist-03 section 4.1 allows only ASCII
			// digits.
			signed := strings.HasPrefix(value, "+") || strings.HasPrefix(value, "-")
			persistUntilVal, err := strconv.ParseInt(value, 10, 64)
			if err != nil || signed {
				return issuer, nil, fmt.Errorf("malformed persistUntil timestamp %q", value)
			}
			// time.Unix overflows for values near 2^63-1, which would make a
			// far-future persistUntil read as already expired. Clamp to
			// 9999-12-31T23:59:59Z, the latest time a Timestamp proto can
			// carry.
			persistUntilVal = min(persistUntilVal, 253402300799)
			params.persistUntil = time.Unix(persistUntilVal, 0).UTC()

		default:
			// Per draft-ietf-acme-dns-persist-03, "the server MUST ignore
			// parameters whose names it does not recognize".
			continue
		}
	}
	if params.accountURI == "" {
		return issuer, nil, errors.New("missing mandatory accounturi parameter")
	}
	return issuer, params, nil
}

// checkDNSPersistRecord checks whether a parsed dns-persist-01 record
// authorizes issuance for the given account URIs and wildcard status at the
// given time. It returns nil if the record authorizes issuance, a
// berrors.Malformed error if the accounturi is not a well-formed hashed URI,
// or a berrors.Unauthorized error for authorization failures.
func checkDNSPersistRecord(params *dnsPersistIssueValueParams, accountHashPrefix string, validAccountURIs []string, wildcardName bool, validatedAt time.Time) error {
	// Per draft-ietf-acme-dns-persist-03 section 12.3.1, an accounturi which is
	// not a well-formed hashed URI is a syntax error. We accept only the
	// mandatory sha-256 hash algorithm.
	hashAlgAndValue, underPrefix := strings.CutPrefix(params.accountURI, accountHashPrefix)
	hashAlg, hashValue, _ := strings.Cut(hashAlgAndValue, "/")
	digest, decodeErr := base64.RawURLEncoding.DecodeString(hashValue)
	if !underPrefix || hashAlg != "sha-256" || decodeErr != nil || len(digest) != sha256.Size {
		return berrors.MalformedError("accounturi %q is not of the form \"%ssha-256/<base64url SHA-256 digest>\"",
			params.accountURI, accountHashPrefix)
	}
	// Per draft-ietf-acme-dns-persist-03 section 4.1, accounturi values are
	// compared using Simple String Comparison per RFC 3986 section 6.2.1, with
	// no case-folding or other normalization.
	if !slices.Contains(validAccountURIs, params.accountURI) {
		return berrors.UnauthorizedError("accounturi mismatch: %q does not match any value expected for this account", params.accountURI)
	}
	// Per draft-ietf-acme-dns-persist-03 section 4.1, the policy parameter's
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

func (va *ValidationAuthorityImpl) validateDNSPersist01(ctx context.Context, ident identifier.ACMEIdentifier, validAccountURIs []string, wildcardName bool) ([]core.ValidationRecord, *dnsPersistIssueValueParams, error) {
	if ident.Type != identifier.TypeDNS {
		return nil, nil, berrors.MalformedError("Identifier type for DNS-PERSIST-01 challenge was not DNS")
	}

	if va.issuerDomain == "" {
		return nil, nil, berrors.InternalServerError("no issuer domain name configured for DNS-PERSIST-01 challenge validation")
	}

	if va.accountHashPrefix == "" {
		return nil, nil, berrors.InternalServerError("no account hash prefix configured for DNS-PERSIST-01 challenge validation")
	}

	challengeSubdomain := fmt.Sprintf("%s.%s", core.DNSPersistPrefix, ident.Value)
	txts, resolver, err := va.dnsClient.LookupTXT(ctx, challengeSubdomain)
	if err != nil {
		return nil, nil, berrors.DNSError("Retrieving TXT records for DNS-PERSIST-01 challenge: %s", err)
	}
	if len(txts.Final) == 0 {
		return nil, nil, berrors.UnauthorizedError("No TXT record found at %s", challengeSubdomain)
	}
	validatedAt := va.clk.Now().UTC()

	var syntaxErrs []string
	var authorizationErrs []string
	var latest *dnsPersistIssueValueParams
	for _, rr := range txts.Final {
		record := strings.Join(rr.Txt, "")

		receivedIssuer, params, err := parseDNSPersistRecord(record)
		if err != nil {
			if receivedIssuer == va.issuerDomain {
				syntaxErrs = append(syntaxErrs, fmt.Sprintf(
					"Parsing TXT record at %s with issuer-domain-name %q: %s", challengeSubdomain, receivedIssuer, err))
			}
			// Record is malformed, skip.
			continue
		}
		if receivedIssuer != va.issuerDomain {
			// Record is well-formed but for a different CA, skip.
			continue
		}

		err = checkDNSPersistRecord(params, va.accountHashPrefix, validAccountURIs, wildcardName, validatedAt)
		if errors.Is(err, berrors.Malformed) {
			syntaxErrs = append(syntaxErrs, fmt.Sprintf(
				"Parsing TXT record at %s with issuer-domain-name %q: %s", challengeSubdomain, receivedIssuer, err))
			continue
		}
		if err != nil {
			authorizationErrs = append(authorizationErrs, fmt.Sprintf(
				"Checking TXT record at %s with issuer-domain-name %q: %s", challengeSubdomain, receivedIssuer, err))
			continue
		}

		// Rely on the record which permits the latest expiration, so that the
		// result does not depend on the order of the records.
		if latest == nil || params.persistUntil.IsZero() ||
			(!latest.persistUntil.IsZero() && params.persistUntil.After(latest.persistUntil)) {
			latest = params
		}
	}

	if latest != nil {
		return []core.ValidationRecord{{
			Hostname:      ident.Value,
			ResolverAddrs: []string{resolver},
		}}, latest, nil
	}
	if len(authorizationErrs) > 0 {
		return nil, nil, berrors.UnauthorizedError("%s", strings.Join(authorizationErrs, "; "))
	}
	if len(syntaxErrs) > 0 {
		return nil, nil, berrors.MalformedError("%s", strings.Join(syntaxErrs, "; "))
	}
	return nil, nil, berrors.UnauthorizedError("No valid TXT record found at %s", challengeSubdomain)
}
