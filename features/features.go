package features

import (
	"fmt"
)

// List of features and their default value
var features = map[string]bool{
	"NewVARPC": false,
}

// Set accepts a list of features and whether they should
// be enabled or disabled, it will return a error if passed
// a feature name that it doesn't know
func Set(featureSet map[string]bool) error {
	for n, v := range featureSet {
		if _, present := features[n]; !present {
			return fmt.Errorf("feature '%s' doesn't exist", n)
		}
		features[n] = v
	}
	return nil
}

// Enabled returns true if the feature is enabled or false
// if it isn't, it will panic if passed a feature name that
// it doesn't know
func Enabled(n string) bool {
	v, present := features[n]
	if !present {
		panic(fmt.Sprintf("feature '%s' doesn't exist", n))
	}
	return v
}
