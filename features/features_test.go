package features

import (
	"testing"

	"github.com/letsencrypt/boulder/test"
)

func TestFeatures(t *testing.T) {
	features = map[string]bool{
		"this": true,
		"that": false,
	}

	test.Assert(t, Enabled("this"), "'this' should be enabled")
	test.Assert(t, !Enabled("that"), "'that' should be enabled")

	err := Set(map[string]bool{"and another thing": true})
	test.AssertError(t, err, "Set should've failed trying to enable a non-existent feature")

	err = Set(map[string]bool{"this": false, "that": true})
	test.AssertNotError(t, err, "Set shouldn't have failed setting existing features")
	test.Assert(t, !Enabled("this"), "'this' should be enabled")
	test.Assert(t, Enabled("that"), "'that' should be enabled")
}
