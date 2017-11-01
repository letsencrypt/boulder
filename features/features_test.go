package features

import (
	"testing"

	"github.com/letsencrypt/boulder/test"
)

func TestFeatures(t *testing.T) {
	features = map[FeatureFlag]bool{
		unused: false,
	}
	test.Assert(t, !Enabled(unused), "'unused' shouldn't be enabled")

	err := Set(map[string]bool{"unused": true})
	test.AssertNotError(t, err, "Set shouldn't have failed setting existing features")
	test.Assert(t, Enabled(unused), "'unused' should be enabled")

	Reset()
	test.Assert(t, !Enabled(unused), "'unused' shouldn't be enabled")

	err = Set(map[string]bool{"non-existent": true})
	test.AssertError(t, err, "Set should've failed trying to enable a non-existent feature")

	defer func() {
		if r := recover(); r == nil {
			t.Errorf("Enabled did not panic on an unknown feature")
		}
	}()
	features = map[FeatureFlag]bool{}
	Enabled(unused)
}
