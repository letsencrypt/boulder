// features provides the Config struct, which is used to define feature flags
// that can affect behavior across Boulder components. It also maintains a
// global singleton Config which can be referenced by arbitrary Boulder code
// without having to pass a collection of feature flags through the function
// call graph.
package features

import (
	"sync"
)

// Config contains one boolean field for every Boulder feature flag. It can be
// included directly in an executable's Config struct to have feature flags be
// automatically parsed by the json config loader; executables that do so must
// then call features.Set(parsedConfig) to load the parsed struct into this
// package's global Config.
type Config struct {
	// Deprecated features. Safe for removal once all references to them have
	// been removed from deployed configuration.
	StoreLintingCertificateInsteadOfPrecertificate bool
	LeaseCRLShards                                 bool
	AllowUnrecognizedFeatures                      bool

	// EnforceMultiVA causes the VA to block on remote VA PerformValidation
	// requests in order to make a valid/invalid decision with the results.
	EnforceMultiVA bool
	// MultiVAFullResults will cause the main VA to wait for all of the remote VA
	// results, not just the threshold required to make a decision.
	MultiVAFullResults bool

	// ECDSAForAll enables all accounts, regardless of their presence in the CA's
	// ecdsaAllowedAccounts config value, to get issuance from ECDSA issuers.
	ECDSAForAll bool

	// ServeRenewalInfo exposes the renewalInfo endpoint in the directory and for
	// GET requests. WARNING: This feature is a draft and highly unstable.
	ServeRenewalInfo bool

	// ExpirationMailerUsesJoin enables using a JOIN query in expiration-mailer
	// rather than a SELECT from certificateStatus followed by thousands of
	// one-row SELECTs from certificates.
	ExpirationMailerUsesJoin bool

	// CertCheckerChecksValidations enables an extra query for each certificate
	// checked, to find the relevant authzs. Since this query might be
	// expensive, we gate it behind a feature flag.
	CertCheckerChecksValidations bool

	// CertCheckerRequiresValidations causes cert-checker to fail if the
	// query enabled by CertCheckerChecksValidations didn't find corresponding
	// authorizations.
	CertCheckerRequiresValidations bool

	// CertCheckerRequiresCorrespondence enables an extra query for each certificate
	// checked, to find the linting precertificate in the `precertificates` table.
	// It then checks that the final certificate "corresponds" to the precertificate
	// using `precert.Correspond`.
	CertCheckerRequiresCorrespondence bool

	// AsyncFinalize enables the RA to return approximately immediately from
	// requests to finalize orders. This allows us to take longer getting SCTs,
	// issuing certs, and updating the database; it indirectly reduces the number
	// of issuances that fail due to timeouts during storage. However, it also
	// requires clients to properly implement polling the Order object to wait
	// for the cert URL to appear.
	AsyncFinalize bool

	// AllowNoCommonName defaults to false, and causes the CA to fail to issue a
	// certificate if we can't put a CommonName in it. When true, the
	// CA will be willing to issue certificates with no CN if and only if there
	// is no SAN short enough to be hoisted into the CN.
	//
	// According to the BRs Section 7.1.4.2.2(a), the commonName field is
	// Deprecated, and its inclusion is discouraged but not (yet) prohibited.
	AllowNoCommonName bool

	// CAAAfterValidation causes the VA to only kick off CAA checks after the base
	// domain control validation has completed and succeeded. This makes
	// successful validations slower by serializing the DCV and CAA work, but
	// makes unsuccessful validations easier by not doing CAA work at all.
	CAAAfterValidation bool

	// SHA256SubjectKeyIdentifier enables the generation and use of an RFC 7093
	// compliant truncated SHA256 Subject Key Identifier in end-entity
	// certificates.
	SHA256SubjectKeyIdentifier bool

	// DOH enables DNS-over-HTTPS queries for validation
	DOH bool
}

var fMu = new(sync.RWMutex)
var global = Config{}

// Set changes the global FeatureSet to match the input FeatureSet. This
// overrides any previous changes made to the global FeatureSet.
//
// When used in tests, the caller must defer features.Reset() to avoid leaving
// dirty global state.
func Set(fs Config) {
	fMu.Lock()
	defer fMu.Unlock()
	// If the FeatureSet type ever changes, this must be updated to still copy
	// the input argument, never hold a reference to it.
	global = fs
}

// Reset resets all features to their initial state (false).
func Reset() {
	fMu.Lock()
	defer fMu.Unlock()
	global = Config{}
}

// Get returns a copy of the current global FeatureSet, indicating which
// features are currently enabled (set to true). Expected caller behavior looks
// like:
//
//	if features.Get().FeatureName { ...
func Get() Config {
	fMu.RLock()
	defer fMu.RUnlock()
	// If the FeatureSet type ever changes, this must be updated to still return
	// only a copy of the current state, never a reference directly to it.
	return global
}
