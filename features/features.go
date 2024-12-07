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
	// Deprecated flags.
	IncrementRateLimits bool

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

	// AsyncFinalize enables the RA to return approximately immediately from
	// requests to finalize orders. This allows us to take longer getting SCTs,
	// issuing certs, and updating the database; it indirectly reduces the number
	// of issuances that fail due to timeouts during storage. However, it also
	// requires clients to properly implement polling the Order object to wait
	// for the cert URL to appear.
	AsyncFinalize bool

	// DOH enables DNS-over-HTTPS queries for validation
	DOH bool

	// EnforceMultiCAA causes the VA to kick off remote CAA rechecks when true.
	// When false, no remote CAA rechecks will be performed. The primary VA will
	// make a valid/invalid decision with the results.
	EnforceMultiCAA bool

	// MultipleCertificateProfiles, when enabled, triggers the following
	// behavior:
	//   - SA.NewOrderAndAuthzs: upon receiving a NewOrderRequest with a
	//     `certificateProfileName` value, will add that value to the database's
	//     `orders.certificateProfileName` column. Values in this column are
	//     allowed to be empty.
	MultipleCertificateProfiles bool

	// CheckIdentifiersPaused checks if any of the identifiers in the order are
	// currently paused at NewOrder time. If any are paused, an error is
	// returned to the Subscriber indicating that the order cannot be processed
	// until the paused identifiers are unpaused and the order is resubmitted.
	CheckIdentifiersPaused bool

	// UseKvLimitsForNewOrder when enabled, causes the key-value rate limiter to
	// be the authoritative source of rate limiting information for new-order
	// callers and disables the legacy rate limiting checks.
	//
	// Note: this flag does not disable writes to the certificatesPerName or
	// fqdnSets tables at Finalize time.
	UseKvLimitsForNewOrder bool

	// DisableLegacyLimitWrites when enabled, disables writes to:
	//   - the newOrdersRL table at new-order time, and
	//   - the certificatesPerName table at finalize time.
	//
	// This flag should only be used in conjunction with UseKvLimitsForNewOrder.
	DisableLegacyLimitWrites bool

	// PropagateCancels controls whether the WFE and ocsp-responder allows
	// cancellation of an inbound request to cancel downstream gRPC and other
	// queries. In practice, cancellation of an inbound request is achieved by
	// Nginx closing the connection on which the request was happening. This may
	// help shed load in overcapacity situations. However, note that in-progress
	// database queries (for instance, in the SA) are not cancelled. Database
	// queries waiting for an available connection may be cancelled.
	PropagateCancels bool

	// InsertAuthzsIndividually causes the SA's NewOrderAndAuthzs method to
	// create each new authz one at a time, rather than using MultiInserter.
	// Although this is expected to be a performance penalty, it is necessary to
	// get the AUTO_INCREMENT ID of each new authz without relying on MariaDB's
	// unique "INSERT ... RETURNING" functionality.
	InsertAuthzsIndividually bool

	// AutomaticallyPauseZombieClients configures the RA to automatically track
	// and pause issuance for each (account, hostname) pair that repeatedly
	// fails validation.
	AutomaticallyPauseZombieClients bool

	// NoPendingAuthzReuse causes the RA to only select already-validated authzs
	// to attach to a newly created order. This preserves important client-facing
	// functionality (valid authz reuse) while letting us simplify our code by
	// removing pending authz reuse.
	NoPendingAuthzReuse bool

	// EnforceMPIC enforces SC-067 V3: Require Multi-Perspective Issuance
	// Corroboration by:
	//  - Requiring at least three distinct perspectives, as outlined in the
	//    "Phased Implementation Timeline" in BRs section 3.2.2.9 ("Effective
	//    March 15, 2025").
	//  - Ensuring that corroborating (passing) perspectives reside in at least
	//    2 distinct Regional Internet Registries (RIRs) per the "Phased
	//    Implementation Timeline" in BRs section 3.2.2.9 ("Effective March 15,
	//    2026").
	//  - Including an MPIC summary consisting of: passing perspectives, failing
	//    perspectives, passing RIRs, and a quorum met for issuance (e.g., 2/3
	//    or 3/3) in each validation audit log event, per BRs Section 5.4.1,
	//    Requirement 2.8.
	//
	// This feature flag also causes CAA checks to happen after all remote VAs
	// have passed DCV.
	EnforceMPIC bool
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
