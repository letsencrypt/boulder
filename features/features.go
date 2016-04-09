package features

import (
	"expvar"
	"fmt"
)

// List of features and their default value
var features = map[string]bool{
	"NewVARPC": false,
}

type boolVar bool

// you'd think bool would implement this
func (b boolVar) String() string { return fmt.Sprintf("%t", b) }

// Set accepts a list of features and whether they should
// be enabled or disabled, it will return a error if passed
// a feature name that it doesn't know. It also
func Set(featureSet map[string]bool) error {
	for n, v := range featureSet {
		if _, present := features[n]; !present {
			return fmt.Errorf("feature '%s' doesn't exist", n)
		}
		features[n] = v
	}
	return nil
}

// Export populates a expvar.Map with the state of all
// of the features.
func Export(m *expvar.Map) {
	for n, v := range features {
		m.Set(n, boolVar(v))
	}
}

// Enabled returns true if the feature is enabled or false
// if it isn't, it will panic if passed a feature name that
// it doesn't know.
func Enabled(n string) bool {
	v, present := features[n]
	if !present {
		panic(fmt.Sprintf("feature '%s' doesn't exist", n))
	}
	return v
}
