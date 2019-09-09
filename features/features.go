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
	PerformValidationRPC
	ACME13KeyRollover
	SimplifiedVAHTTP
	TLSSNIRevalidation
	AllowRenewalFirstRL
	SetIssuedNamesRenewalBit
	FasterRateLimit
	ProbeCTLogs
	RevokeAtRA

	//   Currently in-use features
	// Check CAA and respect validationmethods parameter.
	CAAValidationMethods
	// Check CAA and respect accounturi parameter.
	CAAAccountURI
	// HEAD requests to the WFE2 new-nonce endpoint should return HTTP StatusOK
	// instead of HTTP StatusNoContent.
	HeadNonceStatusOK
	// NewAuthorizationSchema enables usage of the new authorization storage schema
	// and associated RPCs.
	NewAuthorizationSchema
	// DisableAuthz2Orders prevents returning orders containing authz2 authorizations
	// from the SA. If a order containing authz2 authorizations is queried a NotFound
	// error will be returned. DisableAuthz2Orders should only be enabled if the authz2
	// schema is in place. DisableAuthz2Orders should not be enabled if NewAuthorizationSchema
	// is enabled as all new orders containing v2 authorizations will be hidden.
	DisableAuthz2Orders
	// EarlyOrderRateLimit enables the RA applying certificate per name/per FQDN
	// set rate limits in NewOrder in addition to FinalizeOrder.
	EarlyOrderRateLimit
	// EnforceMultiVA causes the VA to block on remote VA PerformValidation
	// requests in order to make a valid/invalid decision with the results.
	EnforceMultiVA
	// MultiVAFullResults will cause the main VA to wait for all of the remote VA
	// results, not just the threshold required to make a decision.
	MultiVAFullResults
	// RemoveWFE2AccountID will remove the account ID from account objects returned
	// from the new-account endpoint if enabled.
	RemoveWFE2AccountID
	// CheckRenewalFirst will check whether an issuance is a renewal before
	// checking the "certificates per name" rate limit.
	CheckRenewalFirst
	// MandatoryPOSTAsGET forbids legacy unauthenticated GET requests for ACME
	// resources.
	MandatoryPOSTAsGET
	// Use an optimized query for GetOrderForNames.
	FasterGetOrderForNames
	// Allow creation of new registrations in ACMEv1.
	AllowV1Registration
	// Check the failed validation limit in parallel during NewOrder
	ParallelCheckFailedValidation
	// Upon authorization validation, delete the challenges that weren't used.
	DeleteUnusedChallenges
	// V1DisableNewValidations disables validations for new domain names in the V1
	// API.
	V1DisableNewValidations
	// PrecertificateOCSP ensures that we write an OCSP response immediately upon
	// generating a precertificate. This also changes the issuance / storage flow,
	// adding two new calls from CA to SA: AddSerial and AddPrecertificate.
	PrecertificateOCSP
)

// List of features and their default value, protected by fMu
var features = map[FeatureFlag]bool{
	unused:                        false,
	AllowRenewalFirstRL:           false,
	TLSSNIRevalidation:            false,
	CAAValidationMethods:          false,
	CAAAccountURI:                 false,
	ACME13KeyRollover:             false,
	ProbeCTLogs:                   false,
	SimplifiedVAHTTP:              false,
	PerformValidationRPC:          false,
	HeadNonceStatusOK:             false,
	NewAuthorizationSchema:        false,
	RevokeAtRA:                    false,
	SetIssuedNamesRenewalBit:      false,
	EarlyOrderRateLimit:           false,
	EnforceMultiVA:                false,
	MultiVAFullResults:            false,
	RemoveWFE2AccountID:           false,
	FasterRateLimit:               false,
	CheckRenewalFirst:             false,
	MandatoryPOSTAsGET:            false,
	DisableAuthz2Orders:           false,
	FasterGetOrderForNames:        false,
	AllowV1Registration:           true,
	ParallelCheckFailedValidation: false,
	DeleteUnusedChallenges:        false,
	V1DisableNewValidations:       false,
	PrecertificateOCSP:            false,
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
