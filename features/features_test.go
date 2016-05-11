package features

import (
	"testing"

	"github.com/letsencrypt/boulder/test"
)

func TestFeatures(t *testing.T) {
	features = map[FeatureFlag]bool{
		NewVARPC: false,
	}
	test.Assert(t, !Enabled(NewVARPC), "'NewVARPC' shouldn't be enabled")
	err := Set(map[string]bool{"NewVARPC": true})
	test.AssertNotError(t, err, "Set shouldn't have failed setting existing features")
	test.Assert(t, Enabled(NewVARPC), "'NewVARPC' should be enabled")
	err = Set(map[string]bool{"non-existent": true})
	test.AssertError(t, err, "Set should've failed trying to enable a non-existent feature")
}
