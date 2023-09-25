//go:generate stringer -type=FeatureFlag

package features

import (
	"fmt"
	"strings"
	"sync"
)

type FeatureFlag int

const (
	unused FeatureFlag = iota // unused is used for testing
	//   Deprecated features, these can be removed once stripped from production configs
	StoreRevokerInfo
	ROCSPStage6
	ROCSPStage7
	StoreLintingCertificateInsteadOfPrecertificate
	CAAValidationMethods
	CAAAccountURI
	LeaseCRLShards

	//   Currently in-use features
	// EnforceMultiVA causes the VA to block on remote VA PerformValidation
	// requests in order to make a valid/invalid decision with the results.
	EnforceMultiVA
	// MultiVAFullResults will cause the main VA to wait for all of the remote VA
	// results, not just the threshold required to make a decision.
	MultiVAFullResults
	// ECDSAForAll enables all accounts, regardless of their presence in the CA's
	// ecdsaAllowedAccounts config value, to get issuance from ECDSA issuers.
	ECDSAForAll
	// ServeRenewalInfo exposes the renewalInfo endpoint in the directory and for
	// GET requests. WARNING: This feature is a draft and highly unstable.
	ServeRenewalInfo
	// AllowUnrecognizedFeatures is internal to the features package: if true,
	// skip error when unrecognized feature flag names are passed.
	AllowUnrecognizedFeatures

	// ExpirationMailerUsesJoin enables using a JOIN query in expiration-mailer
	// rather than a SELECT from certificateStatus followed by thousands of
	// one-row SELECTs from certificates.
	ExpirationMailerUsesJoin

	// CertCheckerChecksValidations enables an extra query for each certificate
	// checked, to find the relevant authzs. Since this query might be
	// expensive, we gate it behind a feature flag.
	CertCheckerChecksValidations

	// CertCheckerRequiresValidations causes cert-checker to fail if the
	// query enabled by CertCheckerChecksValidations didn't find corresponding
	// authorizations.
	CertCheckerRequiresValidations

	// CertCheckerRequiresCorrespondence enables an extra query for each certificate
	// checked, to find the linting precertificate in the `precertificates` table.
	// It then checks that the final certificate "corresponds" to the precertificate
	// using `precert.Correspond`.
	CertCheckerRequiresCorrespondence

	// AsyncFinalize enables the RA to return approximately immediately from
	// requests to finalize orders. This allows us to take longer getting SCTs,
	// issuing certs, and updating the database; it indirectly reduces the number
	// of issuances that fail due to timeouts during storage. However, it also
	// requires clients to properly implement polling the Order object to wait
	// for the cert URL to appear.
	AsyncFinalize

	// RequireCommonName defaults to true, and causes the CA to fail to issue a
	// certificate if there is no CommonName in the certificate. When false, the
	// CA will be willing to issue certificates with no CN.
	//
	// According to the BRs Section 7.1.4.2.2(a), the commonName field is
	// Deprecated, and its inclusion is discouraged but not (yet) prohibited.
	RequireCommonName

	// CAAAfterValidation causes the VA to only kick off CAA checks after the base
	// domain control validation has completed and succeeded. This makes
	// successful validations slower by serializing the DCV and CAA work, but
	// makes unsuccessful validations easier by not doing CAA work at all.
	CAAAfterValidation
)

// List of features and their default value, protected by fMu
var features = map[FeatureFlag]bool{
	unused:                            false,
	CAAValidationMethods:              false,
	CAAAccountURI:                     false,
	EnforceMultiVA:                    false,
	MultiVAFullResults:                false,
	StoreRevokerInfo:                  false,
	ECDSAForAll:                       false,
	ServeRenewalInfo:                  false,
	AllowUnrecognizedFeatures:         false,
	ROCSPStage6:                       false,
	ROCSPStage7:                       false,
	ExpirationMailerUsesJoin:          false,
	CertCheckerChecksValidations:      false,
	CertCheckerRequiresValidations:    false,
	CertCheckerRequiresCorrespondence: false,
	AsyncFinalize:                     false,
	RequireCommonName:                 true,
	LeaseCRLShards:                    false,
	CAAAfterValidation:                false,

	StoreLintingCertificateInsteadOfPrecertificate: false,
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
// be enabled or disabled. In the presence of unrecognized
// flags, it will return an error or not depending on the
// value of AllowUnrecognizedFeatures.
func Set(featureSet map[string]bool) error {
	fMu.Lock()
	defer fMu.Unlock()
	var unknown []string
	for n, v := range featureSet {
		f, present := nameToFeature[n]
		if present {
			features[f] = v
		} else {
			unknown = append(unknown, n)
		}
	}
	if len(unknown) > 0 && !features[AllowUnrecognizedFeatures] {
		return fmt.Errorf("unrecognized feature flag names: %s",
			strings.Join(unknown, ", "))
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
