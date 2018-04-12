//go:generate stringer -type=FeatureFlag

package features

import (
	"fmt"
	"sync"
)

type FeatureFlag int

const (
	unused FeatureFlag = iota // unused is used for testing
	UseAIAIssuerURL
	// For new-authz requests, if there is no valid authz, but there is a pending
	// authz, return that instead of creating a new one.
	ReusePendingAuthz
	CountCertificatesExact
	IPv6First
	AllowRenewalFirstRL
	// Allow issuance of wildcard domains for ACMEv2
	WildcardDomains
	// Copy authz status to challenge status
	ForceConsistentStatus
	// Enforce prevention of use of disabled challenge types
	EnforceChallengeDisable
	// Ensure there is headroom in RPC timeouts to return an error to the client
	RPCHeadroom
	// Allow TLS-SNI in new-authz that are revalidating for previous issuance
	TLSSNIRevalidation
	EmbedSCTs
	CancelCTSubmissions
	VAChecksGSB
	// Return errors to ACMEv2 clients that do not send the correct JWS
	// Content-Type header
	EnforceV2ContentType
	// Reject new-orders that contain a hostname redundant with a wildcard.
	EnforceOverlappingWildcards
)

// List of features and their default value, protected by fMu
var features = map[FeatureFlag]bool{
	unused:                      false,
	UseAIAIssuerURL:             false,
	ReusePendingAuthz:           false,
	CountCertificatesExact:      false,
	IPv6First:                   false,
	AllowRenewalFirstRL:         false,
	WildcardDomains:             false,
	EnforceChallengeDisable:     false, // deprecated
	RPCHeadroom:                 false,
	TLSSNIRevalidation:          false,
	EmbedSCTs:                   false,
	CancelCTSubmissions:         true,
	VAChecksGSB:                 false,
	EnforceV2ContentType:        false,
	ForceConsistentStatus:       false,
	EnforceOverlappingWildcards: false,
}

var fMu = new(sync.RWMutex)

var initial = map[FeatureFlag]bool{}

var nameToFeature = make(map[string]FeatureFlag, len(features))

func init() {
	for f, v := range features {
		nameToFeature[f.String()] = f
		initial[f] = v
	}
}

// Set accepts a list of features and whether they should
// be enabled or disabled, it will return a error if passed
// a feature name that it doesn't know
func Set(featureSet map[string]bool) error {
	fMu.Lock()
	defer fMu.Unlock()
	for n, v := range featureSet {
		f, present := nameToFeature[n]
		if !present {
			return fmt.Errorf("feature '%s' doesn't exist", n)
		}
		features[f] = v
	}
	return nil
}

// Enabled returns true if the feature is enabled or false
// if it isn't, it will panic if passed a feature that it
// doesn't know.
func Enabled(n FeatureFlag) bool {
	fMu.RLock()
	defer fMu.RUnlock()
	v, present := features[n]
	if !present {
		panic(fmt.Sprintf("feature '%s' doesn't exist", n.String()))
	}
	return v
}

// Reset resets the features to their initial state
func Reset() {
	fMu.Lock()
	defer fMu.Unlock()
	for k, v := range initial {
		features[k] = v
	}
}
