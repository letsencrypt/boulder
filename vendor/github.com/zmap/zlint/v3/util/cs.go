package util

import "github.com/zmap/zcrypto/encoding/asn1"

const (
	evCodeSigningPolicy = "2.23.140.1.3"
	codeSigningPolicy   = "2.23.140.1.4.1"
)

func IsCodeSigning(policies []asn1.ObjectIdentifier) bool {
	for _, policy := range policies {
		if policy.String() == evCodeSigningPolicy || policy.String() == codeSigningPolicy {
			return true
		}
	}

	return false
}
