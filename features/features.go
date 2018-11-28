//go:generate stringer -type=FeatureFlag

package features

import (
	"fmt"
	"sync"
)

type FeatureFlag int

const (
	unused FeatureFlag = iota // unused is used for testing
	//   Deprecated features, these can be removed once stripped from production configs
	ReusePendingAuthz
	CancelCTSubmissions
	CountCertificatesExact
	IPv6First
	EnforceChallengeDisable
	EmbedSCTs
	WildcardDomains
	ForceConsistentStatus
	RPCHeadroom
	VAChecksGSB
	EnforceV2ContentType
	EnforceOverlappingWildcards
	OrderReadyStatus

	//   Currently in-use features
	AllowRenewalFirstRL
	// Allow TLS-SNI in new-authz that are revalidating for previous issuance
	TLSSNIRevalidation
	// Check CAA and respect validationmethods parameter.
	CAAValidationMethods
	// Check CAA and respect accounturi parameter.
	CAAAccountURI
	// Honour draft-ietf-acme-13's keyrollover
	ACME13KeyRollover
	// ProbeCTLogs enables HTTP probes to CT logs from the publisher
	ProbeCTLogs
	// SimplifiedVAHTTP enables the simplified VA http-01 rewrite that doesn't use
	// a custom dialer.
	SimplifiedVAHTTP
	// PerformValidationRPC enables the WFE/WFE2 to use the RA's PerformValidation
	// RPC instead of the deprecated UpdateAuthorization RPC.
	PerformValidationRPC
)

// List of features and their default value, protected by fMu
var features = map[FeatureFlag]bool{
	unused:                      false,
	ReusePendingAuthz:           false,
	CountCertificatesExact:      false,
	IPv6First:                   false,
	AllowRenewalFirstRL:         false,
	WildcardDomains:             false,
	EnforceChallengeDisable:     false,
	RPCHeadroom:                 false,
	TLSSNIRevalidation:          false,
	EmbedSCTs:                   false,
	CancelCTSubmissions:         true,
	VAChecksGSB:                 false,
	EnforceV2ContentType:        false,
	ForceConsistentStatus:       false,
	EnforceOverlappingWildcards: false,
	OrderReadyStatus:            false,
	CAAValidationMethods:        false,
	CAAAccountURI:               false,
	ACME13KeyRollover:           false,
	ProbeCTLogs:                 false,
	SimplifiedVAHTTP:            false,
	PerformValidationRPC:        false,
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
