//go:generate stringer -type=FeatureFlag

package features

import (
	"expvar"
	"fmt"
	"sync"
)

type FeatureFlag int

const (
	unused                    FeatureFlag = iota
	DNSAllowLoopbackAddresses             // Common
	CheckMalformedCSR                     // WFE
	DoNotForceCN                          // RA, CA
	ReuseValidAuthz                       // RA
	EnableMustStaple                      // CA
)

// List of features and their default value
var features = map[FeatureFlag]bool{
	unused: false,
	DNSAllowLoopbackAddresses: false,
	CheckMalformedCSR:         false,
	DoNotForceCN:              false,
	ReuseValidAuthz:           false,
	EnableMustStaple:          false,
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

type boolVar bool

// you'd think bool would implement this itself
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
		panic(fmt.Sprintf("feature '%s' doesn't exist", n))
	}
	return v
}

// Reset resets the features to their initial state
func Reset() {
	fMu.Lock()
	defer fMu.Unlock()
	features = initial
}
