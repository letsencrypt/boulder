//go:generate stringer -type=FeatureFlag

package features

import (
	"expvar"
	"fmt"
)

type FeatureFlag int

const (
	NewVARPC FeatureFlag = iota
)

// List of features and their default value
var features = map[FeatureFlag]bool{
	NewVARPC: false,
}

var nameToFeature = make(map[string]FeatureFlag, len(features))

func init() {
	for f := range features {
		nameToFeature[f.String()] = f
	}
}

type boolVar bool

// you'd think bool would implement this itself
func (b boolVar) String() string { return fmt.Sprintf("%t", b) }

// Set accepts a list of features and whether they should
// be enabled or disabled, it will return a error if passed
// a feature name that it doesn't know
func Set(featureSet map[string]bool) error {
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
	for f, v := range features {
		m.Set(f.String(), boolVar(v))
	}
}

// Enabled returns true if the feature is enabled or false
// if it isn't, it will panic if passed a feature that it
// doesn't know.
func Enabled(n FeatureFlag) bool {
	v, present := features[n]
	if !present {
		panic(fmt.Sprintf("feature '%s' doesn't exist", n))
	}
	return v
}
