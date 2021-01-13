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
	WriteIssuedNamesPrecert
	HeadNonceStatusOK
	RemoveWFE2AccountID
	CheckRenewalFirst
	ParallelCheckFailedValidation
	DeleteUnusedChallenges
	BlockedKeyTable
	StoreKeyHashes
	PrecertificateRevocation

	//   Currently in-use features
	// Check CAA and respect validationmethods parameter.
	CAAValidationMethods
	// Check CAA and respect accounturi parameter.
	CAAAccountURI
	// EnforceMultiVA causes the VA to block on remote VA PerformValidation
	// requests in order to make a valid/invalid decision with the results.
	EnforceMultiVA
	// MultiVAFullResults will cause the main VA to wait for all of the remote VA
	// results, not just the threshold required to make a decision.
	MultiVAFullResults
	// MandatoryPOSTAsGET forbids legacy unauthenticated GET requests for ACME
	// resources.
	MandatoryPOSTAsGET
	// Allow creation of new registrations in ACMEv1.
	AllowV1Registration
	// V1DisableNewValidations disables validations for new domain names in the V1
	// API.
	V1DisableNewValidations
	// StripDefaultSchemePort enables stripping of default scheme ports from HTTP
	// request Host headers
	StripDefaultSchemePort
	// StoreIssuerInfo enables storage of information identifying the issuer of
	// a certificate in the certificateStatus table.
	StoreIssuerInfo
	// StoreRevokerInfo enables storage of the revoker and a bool indicating if the row
	// was checked for extant unrevoked certificates in the blockedKeys table.
	StoreRevokerInfo
	// RestrictRSAKeySizes enables restriction of acceptable RSA public key moduli to
	// the common sizes (2048, 3072, and 4096 bits).
	RestrictRSAKeySizes
	// FasterNewOrdersRateLimit enables use of a separate table for counting the
	// new orders rate limit.
	FasterNewOrdersRateLimit
	// NonCFSSLSigner enables usage of our own certificate signer instead of the
	// CFSSL signer.
	NonCFSSLSigner
)

// List of features and their default value, protected by fMu
var features = map[FeatureFlag]bool{
	unused:                        false,
	CAAValidationMethods:          false,
	CAAAccountURI:                 false,
	HeadNonceStatusOK:             false,
	EnforceMultiVA:                false,
	MultiVAFullResults:            false,
	RemoveWFE2AccountID:           false,
	CheckRenewalFirst:             false,
	MandatoryPOSTAsGET:            false,
	AllowV1Registration:           true,
	ParallelCheckFailedValidation: false,
	DeleteUnusedChallenges:        false,
	V1DisableNewValidations:       false,
	PrecertificateRevocation:      false,
	StripDefaultSchemePort:        false,
	StoreIssuerInfo:               false,
	WriteIssuedNamesPrecert:       false,
	StoreKeyHashes:                false,
	StoreRevokerInfo:              false,
	RestrictRSAKeySizes:           false,
	FasterNewOrdersRateLimit:      false,
	BlockedKeyTable:               false,
	NonCFSSLSigner:                false,
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
