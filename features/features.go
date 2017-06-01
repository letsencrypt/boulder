//go:generate stringer -type=FeatureFlag

package features

import (
	"expvar"
	"fmt"
	"sync"
)

type FeatureFlag int

const (
	unused FeatureFlag = iota // unused is used for testing
	IDNASupport
	AllowAccountDeactivation
	AllowKeyRollover
	ResubmitMissingSCTsOnly
	GoogleSafeBrowsingV4
	UseAIAIssuerURL
	AllowTLS02Challenges
	GenerateOCSPEarly
	// For new-authz requests, if there is no valid authz, but there is a pending
	// authz, return that instead of creating a new one.
	ReusePendingAuthz
	CountCertificatesExact
	RandomDirectoryEntry
	IPv6First
	DirectoryMeta
)

// List of features and their default value, protected by fMu
var features = map[FeatureFlag]bool{
	unused:                   false,
	IDNASupport:              false,
	AllowAccountDeactivation: false,
	AllowKeyRollover:         false,
	ResubmitMissingSCTsOnly:  false,
	GoogleSafeBrowsingV4:     false,
	UseAIAIssuerURL:          false,
	AllowTLS02Challenges:     false,
	GenerateOCSPEarly:        false,
	ReusePendingAuthz:        false,
	CountCertificatesExact:   false,
	RandomDirectoryEntry:     false,
	IPv6First:                false,
	DirectoryMeta:            false,
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

// expvar.Set requires a type that satisfies the expvar.Var interface,
// since neither string nor bool implement this interface we require
// a basic shim.
type boolVar bool

func (b boolVar) String() string { return fmt.Sprintf("%t", b) }

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

// Export populates a expvar.Map with the state of all
// of the features.
func Export(m *expvar.Map) {
	fMu.RLock()
	defer fMu.RUnlock()
	for f, v := range features {
		m.Set(f.String(), boolVar(v))
	}
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
